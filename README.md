# jtrace

`jtrace` is a Linux tool that tracks the execution flow of a program, saves it and displays diffs between saved runs. It's an after-hours hobby project developed to the working proof-of-concept stage, so it's probably full of bugs and it probably works only for the simplest cases. Some design choices are arbitrary and probably less efficient than alternatives. The code is dense, full of hacks and, generally, is undocumented.

`jtrace` (like debuggers and tools like `strace`) uses the ptrace syscall. The tracee is stopped after the tracer attaches itself with ptrace, then the memory is scanned for branching instructions. Each detected branching instruction is saved and replaced with a trap. After hitting a trap, the execution is continued for one step, and the information whether branch was taken or not is saved into a `<PID>.jtrace` binary file.

That file can be then read with `jtrace-show`, which displays the saved addresses of the branching instructions along with the taken or not information. The `jtrace-diff` uses the [Myers diff algorithm](http://www.xmailserver.org/diff2.pdf) to compute the longest common subsequence between two execution logs from the passed `.jtrace` files, and the difference between these runs is displayed.

# Installation and usage

Simply clone the repo and build the project with cargo:
```
cargo build --release
```

Each executable has a `--help` flag, e.g.:
```
jtrace-diff --help
```

# Examples
We'll use the binaries from [these simple crackmes](https://github.com/wapiflapi/exrs/tree/master/reverse).

First, we run our target program with different arguments using `jtrace`:
```
[bw@xps13 ~/tmp]$ ~/RustProjs/jtrace/target/release/jtrace -- ~/archive/security/ctf_crackmes/exrs-master/reverse/r3 test
password "test" not OK
[bw@xps13 ~/tmp]$ ~/RustProjs/jtrace/target/release/jtrace -- ~/archive/security/ctf_crackmes/exrs-master/reverse/r3 1337_ptest
password "1337_ptest" not OK
[bw@xps13 ~/tmp]$ ~/RustProjs/jtrace/target/release/jtrace -- ~/archive/security/ctf_crackmes/exrs-master/reverse/r3 1337_pwd
password OK
```

Three `.jtrace` files should appear:
```
[bw@xps13 ~/tmp]$ ls -1
1866083.jtrace
1866102.jtrace
1866119.jtrace
```

We can display the saved execution log with `jtrace-show`:
```
[bw@xps13 ~/tmp]$ ~/RustProjs/jtrace/target/release/jtrace-show 1866083.jtrace
Reading data from 1866083.jtrace
Root parent PID: 1866083
CLI: /home/bw/RustProjs/jtrace/target/release/jtrace -- /home/bw/archive/security/ctf_crackmes/exrs-master/reverse/r3 test
Memory map:
START		END		OFFSET		FLAGS		FILENAME
0x00400000	0x00401000	0x00000000	r-xp		Some("/home/bw/archive/security/ctf_crackmes/exrs-master/reverse/r3")
0x00600000	0x00602000	0x00000000	rw-p		Some("/home/bw/archive/security/ctf_crackmes/exrs-master/reverse/r3")


PID		ADDR		BRANCH
1866083		0x00400426	taken
1866083		0x00400510	not taken
1866083		0x004007b4	not taken
1866083		0x00400724	taken
1866083		0x0040058e	not taken
1866083		0x00400599	not taken
1866083		0x004006eb	taken
1866083		0x004004d3	not taken
```

We can compare different runs with `jtrace-diff`, e.g.:
```
[bw@xps13 ~/tmp]$ ~/RustProjs/jtrace/target/release/jtrace-diff 1866083.jtrace 1866119.jtrace
Diffrences between PID 1866083 and PID 1866119:
...
5:	+ 0x00000599	not taken
5:	+ 0x000005b2	not taken
5:	+ 0x000005c1	not taken
5:	+ 0x000005da	not taken
5:	+ 0x000005e9	not taken
5:	+ 0x00000602	not taken
5:	+ 0x00000611	not taken
5:	+ 0x0000062a	not taken
5:	+ 0x00000639	not taken
5:	+ 0x00000652	not taken
5:	+ 0x00000661	not taken
5:	+ 0x00000677	not taken
5:	+ 0x00000686	not taken
5:	+ 0x0000069c	not taken
5:	+ 0x000006ab	not taken
6:	- 0x000006eb	taken
7:	- 0x000004d3	not taken
7:	+ 0x000006c1	not taken
7:	+ 0x000006eb	not taken
```