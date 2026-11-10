# AttoLang borrow checker (Rust)

This repository will host the canonical, backend-neutral ownership and borrowing verifier for AttoLang.

The **language contract is shared**, while Java/GraalVM, .NET/C#, LLVM/C++, Wasm and Cranelift may retain local, in-pass ownership checks and target-specific lifetime enforcement. A local compiler may accept a program only where its checks are proven equivalent to the normative rules; unresolved cases must use the shared checker or fail closed.

Initial work is developed through draft pull requests. No general compiler integration or runtime safety certification is implied by this README.
