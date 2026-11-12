//! Independent bounded state-space check, not guest/compiler certification.
use atto_borrow_checker::{cyclic_v1 as cyclic, *};

#[derive(Clone, Copy)]
enum Step {
    Read,
    Write,
    Share,
    Exclusive,
    EndShared,
    EndExclusive,
    Drop,
    Suspend,
    WriteThrough,
}

const STEPS: [Step; 9] = [
    Step::Read,
    Step::Write,
    Step::Share,
    Step::Exclusive,
    Step::EndShared,
    Step::EndExclusive,
    Step::Drop,
    Step::Suspend,
    Step::WriteThrough,
];

// A separate straight-line specification: no CFG joins or solver state.
fn allowed(steps: &[Step]) -> bool {
    let (mut live, mut shared, mut exclusive) = (true, false, false);
    let (mut shared_used, mut exclusive_used) = (false, false);
    for step in steps {
        let valid = match step {
            Step::Read => live && !exclusive,
            Step::Write => live && !shared && !exclusive,
            Step::Share => {
                let valid = live && !exclusive && !shared_used;
                shared = true;
                shared_used = true;
                valid
            }
            Step::Exclusive => {
                let valid = live && !shared && !exclusive && !exclusive_used;
                exclusive = true;
                exclusive_used = true;
                valid
            }
            Step::EndShared => {
                let valid = shared;
                shared = false;
                valid
            }
            Step::EndExclusive => {
                let valid = exclusive;
                exclusive = false;
                valid
            }
            Step::Drop => {
                let valid = live && !shared && !exclusive;
                live = false;
                valid
            }
            Step::Suspend => !shared && !exclusive,
            Step::WriteThrough => live && exclusive,
        };
        if !valid {
            return false;
        }
    }
    !shared && !exclusive
}

fn check(steps: &[Step]) {
    let mut operations = vec![Op::Init {
        owner: 1,
        traits: Traits {
            is_copy: false,
            is_send: false,
        },
    }];
    let mut ops = Vec::new();
    for step in steps {
        let place = cyclic::Place::root(1);
        let (v0, v1) = match step {
            Step::Read => (Op::Read { owner: 1 }, cyclic::Op::Read(place)),
            Step::Write => (Op::Write { owner: 1 }, cyclic::Op::Write(place)),
            Step::Share => (
                Op::Borrow {
                    owner: 1,
                    loan: 1,
                    kind: BorrowKind::Shared,
                },
                cyclic::Op::Borrow {
                    loan: 1,
                    place,
                    kind: cyclic::LoanKind::Shared,
                },
            ),
            Step::Exclusive => (
                Op::Borrow {
                    owner: 1,
                    loan: 2,
                    kind: BorrowKind::Mutable,
                },
                cyclic::Op::Borrow {
                    loan: 2,
                    place,
                    kind: cyclic::LoanKind::Exclusive,
                },
            ),
            Step::EndShared => (Op::EndBorrow { loan: 1 }, cyclic::Op::EndLoan(1)),
            Step::EndExclusive => (Op::EndBorrow { loan: 2 }, cyclic::Op::EndLoan(2)),
            Step::Drop => (Op::Drop { owner: 1 }, cyclic::Op::Drop(place)),
            Step::Suspend => (Op::Suspend, cyclic::Op::Suspend),
            Step::WriteThrough => (
                Op::WriteThrough { owner: 1, loan: 2 },
                cyclic::Op::WriteThrough(2),
            ),
        };
        operations.push(v0);
        ops.push(v1);
    }
    operations.push(Op::Return);
    let expected = allowed(steps);
    assert_eq!(
        verify(&Program {
            entry: 0,
            blocks: vec![Block {
                id: 0,
                operations,
                successors: vec![]
            }],
        })
        .is_ok(),
        expected,
        "V0 sequence length {}",
        steps.len()
    );
    assert_eq!(
        cyclic::check(&cyclic::Program {
            entry: 0,
            roots: vec![cyclic::Root {
                id: 1,
                is_copy: false,
                is_transferable: false
            }],
            blocks: vec![cyclic::Block {
                id: 0,
                ops,
                successors: vec![]
            }],
        })
        .is_ok(),
        expected,
        "cyclic sequence length {}",
        steps.len()
    );
}

#[test]
fn all_66430_sequences_up_to_five_operations_match_independent_specification() {
    fn enumerate(steps: &mut Vec<Step>, remaining: usize, count: &mut usize) {
        check(steps);
        *count += 1;
        if remaining == 0 {
            return;
        }
        for step in STEPS {
            steps.push(step);
            enumerate(steps, remaining - 1, count);
            steps.pop();
        }
    }
    let mut count = 0;
    enumerate(&mut Vec::new(), 5, &mut count);
    assert_eq!(count, 66_430);
}
