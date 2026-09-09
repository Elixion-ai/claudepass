# Built in Go as a single static binary

`cpass run` executes once per secret-bearing command and the hooks fire on every prompt and every tool call, so startup latency is paid many times per hour. Go gives ~5 ms startup, one static binary with no runtime on the target (CI boxes included), cross-compilation to macOS and Linux in one step, and mature Keychain and Unix-socket libraries. Node/TypeScript was rejected for its per-invocation startup cost and runtime dependency despite the official MCP SDK; Rust for effort per feature. The binary is named `cpass` because `cp` is taken by Unix.
