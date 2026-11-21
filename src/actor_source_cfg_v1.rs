//! Independently verified fixed-diamond actor-state CFG V1.
 //! This is a bounded source-derived adapter, NOT arbitrary typed MIR or
 //! complete NLL. Both arms are verified regardless of literal branch value.
use crate::cyclic_v1::{self, Block, LoanKind, Op, Place, Program, Root};
const MAX_BYTES:usize=65536;
const MAX_EVENTS:usize=512;
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct DiamondReceipt {
    pub source_sha256:String,
    pub field_count:usize,
    pub branch_events:[usize;2],
    pub reachable_blocks:usize,
}
fn parts<'a>(s:&'a str,name:&str,n:usize)->Result<Vec<&'a str>,String>{
    let v:Vec<_>=s.split('\t').collect();
    if v.len()!=n || v[0]!=name {return Err(format!("invalid {name} record"));}
    Ok(v)
}
fn num(s:&str)->Result<usize,String>{
    if s.is_empty()||s.len()>10||!s.bytes().all(|b|b.is_ascii_digit())||
       (s.len()>1&&s.starts_with('0')) {
        return Err("noncanonical integer".into());
    }
    s.parse::<usize>().map_err(|_|"numeric overflow".into())
}
fn get<'a>(lines:&mut impl Iterator<Item=&'a str>,need:&str)->Result<(),String>{
    if lines.next()!=Some(need) {return Err(format!("missing {need}"));}
    Ok(())
}
pub fn verify_bounded_diamond_wire(s:&str)->Result<DiamondReceipt,String>{
    if s.is_empty() || s.len()>MAX_BYTES || !s.ends_with('\n') ||
       s.as_bytes().iter().any(|b| *b==b'\r'||*b==0) {
        return Err("invalid diamond wire bytes".into());
    }
    let mut lines=s.lines();
    let hdr=parts(lines.next().ok_or("missing header")?,"ATTO_ACTOR_STATE_CFG_V1",2)?;
    let digest=hdr[1];
    if digest.len()!=64||!digest.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("invalid source digest".into());
    }
    let root=parts(lines.next().ok_or("missing root")?,"ROOT",3)?;
    if root[1]!="1" {return Err("invalid root ID".into());}
    let count=num(root[2])?;
    if !(1..=256).contains(&count) {return Err("invalid field inventory".into());}
    let loan=parts(lines.next().ok_or("missing loan")?,"LOAN",3)?;
    if loan[1]!="1" {return Err("invalid loan identity".into());}
    let kind=match loan[2] {
        "EXCLUSIVE"=>LoanKind::Exclusive,
        "SHARED"=>LoanKind::Shared,
        _=>return Err("invalid loan permission".into())
    };
    get(&mut lines,"BLOCK\t0")?;
    get(&mut lines,"BORROW\t1")?;
    let branch=parts(lines.next().ok_or("missing branch")?,"BRANCH",4)?;
    if !matches!(branch[1],"TRUE"|"FALSE")||branch[2]!="1"||branch[3]!="2"{
        return Err("unproven branch edges".into());
    }
    let mut blocks=vec![Block { id:0,ops:vec![Op::Borrow {
        loan:1,place:Place::root(1),kind
    }],successors:vec![1,2]}];
    let mut event_counts=[0,0];
    for arm in 0..2usize {
        get(&mut lines,&format!("BLOCK\t{}",arm+1))?;
        let mut ops=vec![];
        loop {
            let line=lines.next().ok_or("missing branch end")?;
            if line=="END\t1" {break;}
            if event_counts[arm]>=MAX_EVENTS || event_counts.iter().sum::<usize>()>=MAX_EVENTS {
                return Err("diamond event budget exceeded".into());
            }
            let fields:Vec<_>=line.split('\t').collect();
            if fields.len()!=4{return Err("malformed field event".into());}
            let field=num(fields[1])?;
            if field>=count||num(fields[2])?==0||num(fields[3])?==0 {
                return Err("out-of-range field or source span".into());
            }
            match fields[0] {
                "READ"=>ops.push(Op::ReadThrough(1)),
                "WRITE" if kind==LoanKind::Exclusive=>ops.push(Op::WriteThrough(1)),
                "WRITE"=>return Err("shared loan cannot write".into()),
                _=>return Err("unknown effect event".into())
            }
            event_counts[arm]+=1;
        }
        if event_counts[arm]==0{return Err("empty conditional branch".into());}
        get(&mut lines,"GOTO\t3")?;
        ops.push(Op::EndLoan(1)); // ended after last observed use on each path
        blocks.push(Block{id:(arm+1) as u32,ops,successors:vec![3]});
    }
    get(&mut lines,"BLOCK\t3")?;
    get(&mut lines,"RETURN")?;
    get(&mut lines,"DONE")?;
    if lines.next().is_some() {return Err("extra/unauthenticated CFG records".into());}
    blocks.push(Block{id:3,ops:vec![Op::Nop],successors:vec![]});
    let program=Program {roots:vec![Root {
        id:1,is_copy:false,is_transferable:false
    }],blocks,entry:0};
    let report=cyclic_v1::check(&program).map_err(|e|
        format!("independent CFG rejected {:?} at {}:{}",e.code,e.block,e.operation))?;
    if report.reachable_blocks!=4 {return Err("incomplete CFG reachability".into());}
    Ok(DiamondReceipt {
        source_sha256:digest.to_owned(),field_count:count,
        branch_events:event_counts,reachable_blocks:report.reachable_blocks
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good()->String {
        format!("ATTO_ACTOR_STATE_CFG_V1\t{}\nROOT\t1\t2\nLOAN\t1\tEXCLUSIVE\nBLOCK\t0\nBORROW\t1\nBRANCH\tTRUE\t1\t2\nBLOCK\t1\nWRITE\t0\t8\t1\nEND\t1\nGOTO\t3\nBLOCK\t2\nREAD\t1\t10\t2\nEND\t1\nGOTO\t3\nBLOCK\t3\nRETURN\nDONE\n", "a".repeat(64))
    }
    #[test]
    fn independent_diamond_checks_all_edges_and_join_lifetime(){
        let receipt=verify_bounded_diamond_wire(&good()).unwrap();
        assert_eq!(receipt.branch_events,[1,1]);
        assert_eq!(receipt.reachable_blocks,4);
    }
    #[test]
    fn missing_arm_end_edges_and_loans_fail_closed(){
        for bad in [
            good().replace("END\t1\nGOTO\t3\nBLOCK\t2","GOTO\t3\nBLOCK\t2"),
            good().replace("BRANCH\tTRUE\t1\t2","BRANCH\tTRUE\t1\t3"),
            good().replace("BLOCK\t2","BLOCK\t9"),
            good().replace("BLOCK\t3\nRETURN","BLOCK\t3\nSUSPEND\nRETURN"),
            good().replace("GOTO\t3","GOTO\t2"),
            good().replace("WRITE\t0\t8\t1","WRITE\t8\t8\t1"),
            good().replace("LOAN\t1\tEXCLUSIVE","LOAN\t1\tSHARED"),
            good().replace("DONE\n","DONE\nDONE\n"),
            good().replace("BRANCH\tTRUE\t1\t2","BRANCH\tMAYBE\t1\t2"),
            good().replace("END\t1\nGOTO\t3\nBLOCK\t2","END\t1\nEND\t1\nGOTO\t3\nBLOCK\t2"),
        ] {
            assert!(verify_bounded_diamond_wire(&bad).is_err(),"must reject {bad}");
        }
    }
}
