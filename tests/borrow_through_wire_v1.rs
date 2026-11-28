use atto_borrow_checker::wire_v1::{decode_op, encode_op, Json, WireOp};
use atto_borrow_checker::Op;

#[test]
fn borrow_through_operations_round_trip_without_losing_proof() {
    for op in [
        Op::ReadThrough { owner: 1, loan: 2 },
        Op::CopyThrough {
            owner: 1,
            loan: 2,
            into: 3,
            detached_proven: true,
        },
        Op::CopyThrough {
            owner: 1,
            loan: 2,
            into: 3,
            detached_proven: false,
        },
    ] {
        assert_eq!(decode_op(&encode_op(&op), "op").unwrap(), WireOp::Op(op));
    }
}

#[test]
fn detached_copy_proof_cannot_be_omitted_or_coerced() {
    let op = Op::CopyThrough {
        owner: 1,
        loan: 2,
        into: 3,
        detached_proven: false,
    };
    let Json::Obj(mut fields) = encode_op(&op) else {
        panic!("operation must be an object");
    };
    fields.retain(|(key, _)| key != "detachedProven");
    assert!(decode_op(&Json::Obj(fields.clone()), "op").is_err());
    fields.push(("detachedProven".into(), Json::Str("true".into())));
    assert!(decode_op(&Json::Obj(fields), "op").is_err());
}
