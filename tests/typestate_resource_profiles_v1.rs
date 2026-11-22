use atto_borrow_checker::typestate_v1::*;

fn verify_ops(protocol: Protocol, ops: Vec<Op>) -> Result<Proof, Diagnostic> {
    verify(&Program { suspending: false,
        entry: 0,
        protocols: vec![protocol],
        blocks: vec![Block { id: 0, ops, successors: vec![] }],
    })
}

fn init(state: StateId) -> Op {
    Op::Init { place: 1, protocol: 9, state }
}

fn call(method: &str) -> Op {
    match method {
        "connect" | "close" | "append" | "finish" => Op::CallMut { place: 1, method: method.into() },
        _ => Op::Call { place: 1, method: method.into() },
    }
}

fn socket() -> Protocol {
    Protocol {
        id: 9,
        name: "Socket".into(),
        states: vec![
            State { id: 0, name: "Disconnected".into(), cleanup: Cleanup::VerifiedDestructor },
            State { id: 1, name: "Connected".into(), cleanup: Cleanup::VerifiedDestructor },
            State { id: 2, name: "Closed".into(), cleanup: Cleanup::Inert },
        ],
        methods: vec![
            Method { name: "connect".into(), from: vec![0], to: Some(1), access: Access::Exclusive , suspends: false },
            Method { name: "send".into(), from: vec![1], to: None, access: Access::Read , suspends: false },
            Method { name: "close".into(), from: vec![0, 1], to: Some(2), access: Access::Exclusive , suspends: false },
        ],
    }
}

#[test]
fn socket_requires_connected_for_send_and_forbids_reconnect_after_close() {
    assert_eq!(
        verify_ops(socket(), vec![init(0), call("send"), Op::Return]).unwrap_err().code,
        "E_TYPESTATE_ILLEGAL_OPERATION"
    );
    assert!(verify_ops(socket(), vec![init(0), call("connect"), call("send"), call("close"), Op::Return]).is_ok());
    assert_eq!(
        verify_ops(socket(), vec![init(0), call("close"), call("connect"), Op::Return]).unwrap_err().code,
        "E_TYPESTATE_ILLEGAL_OPERATION"
    );
}

fn builder() -> Protocol {
    Protocol {
        id: 9,
        name: "Builder".into(),
        states: vec![
            State { id: 0, name: "Unfinished".into(), cleanup: Cleanup::ExplicitTransition },
            State { id: 1, name: "Consumed".into(), cleanup: Cleanup::Inert },
        ],
        methods: vec![
            Method { name: "append".into(), from: vec![0], to: None, access: Access::Exclusive , suspends: false },
            Method { name: "finish".into(), from: vec![0], to: Some(1), access: Access::Exclusive , suspends: false },
        ],
    }
}

#[test]
fn builder_cannot_be_abandoned_or_finished_twice() {
    assert_eq!(
        verify_ops(builder(), vec![init(0), Op::Return]).unwrap_err().code,
        "E_TYPESTATE_INCOMPLETE"
    );
    assert!(verify_ops(builder(), vec![init(0), call("append"), call("finish"), Op::Return]).is_ok());
    assert_eq!(
        verify_ops(builder(), vec![init(0), call("finish"), call("finish"), Op::Return]).unwrap_err().code,
        "E_TYPESTATE_ILLEGAL_OPERATION"
    );
}
