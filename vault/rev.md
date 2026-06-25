---
title: rev
type: note
permalink: ctf-vault/rev
---

# Reverse Engineering — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 19 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## strings/grep instant flag
- category: rev
- signal: Any unknown binary pre-analysis; flag may be a literal or password. Very-easy/easy tag, not packed
- technique: Run strings first, grep the flag format. Pull UTF-16 too for Windows/.NET. Cheapest win
- tool/command: strings -a -n6 ./bin | grep -aiE 'flag\{|ctf\{|HTB\{|pico'; strings -el ./bin | grep -i flag; rabin2 -z ./bin
- gotchas: Misses XOR/encoded/computed flags. Junk strings = packed (suspect UPX). Don't stop at first plausible hit; -tx gives offsets for xref
- frequency: high
- depth: quick
- sources: https://swanandx.github.io/blog/posts/re/ctfs/, https://infosecwriteups.com/htb-cyber-apocalypse-ctf-2024-reversing-d9eb85c59ca9, https://picoctfsolutions.com/posts/ghidra-reverse-engineering

## ltrace strcmp/memcmp leak
- category: rev
- signal: Dynamic-linked binary reads input, prints right/wrong; flag not in strings; visible strcmp/memcmp in decompiler
- technique: Run under ltrace to intercept strcmp/strncmp/memcmp — the expected flag is the compare argument. Also catches open/fopen targets
- tool/command: ltrace -s 200 ./bin <<< 'AAAA' 2>&1 | grep -E 'strcmp|strncmp|memcmp|strcasecmp'
- gotchas: Fails on static/stripped-PLT binaries -> use gdb breakpoint on cmp. Per-char loops leak one byte at a time, read in order. Use -f for forked children
- frequency: high
- depth: quick
- sources: https://swanandx.github.io/blog/posts/re/ctfs/, https://ctf.support/reverse-engineering/decompilers/

## Ghidra main->compare static triage
- category: rev
- signal: Any unknown native binary; first-look triage before choosing a deeper technique
- technique: file+strings+Ghidra: jump to main, read decompiler, follow calls to the compare; expected value, key bytes, or transform usually inline
- tool/command: file ./bin; strings -n6 ./bin | grep -iE 'flag|wrong|correct|key'; Ghidra: Symbol Tree->main->decompile, follow to strcmp/memcmp
- gotchas: Stripped -> find main via __libc_start_main 1st arg. Heavy inlining hides check; statically-linked libc looks like user code -> apply FLIRT/signatures
- frequency: high
- depth: quick
- sources: https://picoctfsolutions.com/posts/ghidra-reverse-engineering, https://swanandx.github.io/blog/posts/re/ctfs/

## gdb breakpoint on comparison (dynamic dump)
- category: rev
- signal: strings/ltrace fail (static, stripped PLT, inlined cmp); decompiler shows a compare/branch deciding success
- technique: Break at the compare instruction, inspect registers/memory holding expected value vs input
- tool/command: gdb ./bin -ex 'b *0xADDR' -ex run -ex 'x/s $rsi' -ex 'x/s $rdi'
- gotchas: PIE: break with `b *main+off` or after `starti` once base known. Per-byte loops: bp inside loop, dump each iter. pwndbg/gef telescope finds the reference reg
- frequency: high
- depth: quick
- sources: https://jaybailey216.com/debugging-stripped-binaries/, https://swanandx.github.io/blog/posts/re/ctfs/

## angr symbolic execution find/avoid
- category: rev
- signal: Single deterministic input check, clear Correct/Wrong branch, no heavy loops/crypto/VM; pure logic
- technique: Explore to success addr (or stdout win string) while avoiding fail; dump stdin from found state
- tool/command: import angr
p=angr.Project('./bin',auto_load_libs=False)
sm=p.factory.simulation_manager(p.factory.full_init_state())
sm.explore(find=lambda s:b'Correct' in s.posix.dumps(1),avoid=lambda s:b'Wrong' in s.posix.dumps(1))
print(sm.found[0].posix.dumps(0))
- gotchas: Path explosion on loops/hashing/VM -> constrain input length+printable bytes or hook scanf/heavy libc. PIE: rebase addrs to 0x400000. find by addr is faster than string match
- frequency: high
- depth: quick
- sources: https://docs.angr.io/en/latest/examples.html, https://book.jorianwoltjer.com/reverse-engineering/angr-solver, https://www.praetorian.com/blog/internetwache-re60-writeup-symbolic-execution-tramples-ctf-challenge/

## angr with preconstrained symbolic stdin
- category: rev
- signal: scanf/fgets reads fixed-length input; per-byte validation, path count manageable but plain find/avoid explodes
- technique: Build symbolic BVS, set as stdin, constrain to printable ASCII to cut paths, explore to success addr
- tool/command: import angr,claripy
p=angr.Project('bin')
flag=claripy.BVS('f',8*32)
st=p.factory.full_init_state(stdin=flag)
[st.solver.add(claripy.Or(b==0,claripy.And(b>=0x20,b<=0x7e))) for b in flag.chop(8)]
sm=p.factory.simulation_manager(st);sm.explore(find=WIN,avoid=FAIL)
print(sm.found[0].solver.eval(flag,cast_to=bytes))
- gotchas: Forgetting ASCII constraints = garbage. cast_to=bytes required. argv input -> entry_state(args=[...]). full_init_state slower but handles libc init
- frequency: med
- depth: quick
- sources: https://docs.angr.io/en/latest/examples.html, https://shivsarthak.medium.com/angr-for-ctf-automating-reversing-a-binary-d5ca574d1d0b

## XOR/add/rol flag deobfuscation
- category: rev
- signal: Decompiler shows a loop XOR/add/rol-ing input or a data blob vs a constant or key array, then memcmp to stored buffer; xxd shows distinct non-printable blob
- technique: Pull stored ciphertext + key from binary, invert ops in exact reverse order in Python/CyberChef. Single-byte keys: brute 256, score printable
- tool/command: python3 -c "enc=bytes.fromhex('...'); key=b'...'; print(bytes((c^key[i%len(key)]) for i,c in enumerate(enc)))"  # add 'then -k' etc to match decompiler
- gotchas: Reverse ops in opposite order of program. Watch endianness for 4/8-byte int keys per-dword, rolling/prev-byte keys, &0xff wrap. ROL/ROR often mixed with XOR
- frequency: high
- depth: quick
- sources: https://swanandx.github.io/blog/posts/re/ctfs/, https://0xdf.gitlab.io/hackvent2019/leet, https://maulvialf.medium.com/write-up-reverse-engineering-htb-apocalypse-2023-936b87b4726

## Z3 constraint-system flag
- category: rev
- signal: Decompiler shows many interdependent arithmetic/bitwise equations over flag bytes (sums, products, XOR chains, modulo) vs constants; angr explodes
- technique: Model each byte as BitVec(8), transcribe every equation as a constraint + printable bounds, solve and concat model
- tool/command: from z3 import *
s=Solver();f=[BitVec(f'f{i}',8) for i in range(N)]
for c in f: s.add(c>=0x20,c<=0x7e)
# s.add(f[0]+f[1]==0x9a); s.add(f[2]^f[3]==0x42) ...
assert s.check()==sat
print(bytes(s.model()[c].as_long() for c in f))
- gotchas: Use BitVec not Int so ops wrap mod 2^n like C. Match exact bit width (8/32/64). Add printable bounds + known prefix (flag{) or get garbage/multiple solutions; add Or(c!=val) to re-solve
- frequency: high
- depth: deep
- sources: https://book.jorianwoltjer.com/cryptography/custom-ciphers/z3-solver, https://medium.com/@attempto/ctf-writeup-twctf2019-easy-crack-me-with-z3-ghidra-and-pwn-3ff5bc732e97, https://github.com/ViRb3/z3-python-ctf

## UPX / packed binary unpack
- category: rev
- signal: strings mostly gibberish + 'UPX!'/UPX0/UPX1 section names; high entropy (binwalk -E); tiny .text stub
- technique: Decompress in place with stock upx -d, then reverse normally. Always unpack BEFORE Ghidra/IDA
- tool/command: strings ./bin | grep -i upx; upx -d ./bin -o unpacked; file unpacked
- gotchas: Tampered UPX magic/version -> patch magic back with hex editor, OR run-and-dump from memory at OEP (gdb break OEP, dump memory). Other packers (ASPack/custom) need manual OEP find
- frequency: high
- depth: quick
- sources: https://medium.com/@idan_malihi/picoctf-unpackme-upx-reverse-engineering-e35da83042f8, https://medium.com/@moromerx/htb-cyber-apocalypse-2024-packed-away-very-easy-1a8ca97e7a22

## .NET managed decompile (dnSpy/ILSpy + de4dot)
- category: rev
- signal: file says Mono/.Net assembly or PE with CLR header; strings show mscorlib/System; obfuscated symbols (method_0, a.b.c) = ConfuserEx
- technique: Decompile to C# in dnSpy/ILSpy; run de4dot first if obfuscated. Set breakpoint or edit-and-rerun the check method to leak runtime-built flags
- tool/command: de4dot app.exe -o clean.exe; ilspycmd clean.exe > app.cs  # or dnSpy: F12 check method, F9 bp, F5, read Locals
- gotchas: dnSpy can't load it? try ILSpy. Strings decrypted at runtime -> use debugger after decrypt. UTF-16 strings: pre-check with strings -el. IL2CPP is NOT managed .NET
- frequency: med
- depth: quick
- sources: https://book.jorianwoltjer.com/reverse-engineering/reversing-c-.net-unity, https://ctf.support/reverse-engineering/decompilers/, https://codingo.io/reverse-engineering/ctf/2017/07/25/Decompiling-CSharp-By-Example-with-Cracknet.html

## Android APK with jadx
- category: rev
- signal: .apk/.aab file; mobile app challenge; flag check in Java/Kotlin, native .so, or resources
- technique: Decompile to Java with jadx, grep source+resources for flag/check; apktool for smali/resources. Native JNI logic -> pull .so, reverse in Ghidra; Frida to hook runtime
- tool/command: jadx -d out app.apk; grep -rniE 'flag|checkFlag|secret|System.loadLibrary' out/; unzip -o app.apk 'lib/*/*.so' res/values/strings.xml -d apk_files
- gotchas: Flag often in strings.xml/assets (base64) or native lib*.so not Java. Obfuscated/R8 -> jadx deobf or Frida hook. AAB -> bundletool first. React Native: assets/index.android.bundle
- frequency: med
- depth: quick
- sources: https://book.jorianwoltjer.com/mobile/reversing-apks, https://ctf.support/reverse-engineering/android/, https://nusgreyhats.org/posts/writeups/introduction-to-android-app-reversing/

## PyInstaller exe / .pyc decompile
- category: rev
- signal: .pyc file, or large .exe whose strings contain PyInstaller/_MEI/python3x.dll
- technique: PyInstaller: extract archive then decompile entrypoint .pyc. Bare .pyc: decompile straight to source
- tool/command: python pyinstxtractor.py app.exe; pycdc app.pyc   # uncompyle6 for py<=3.8
- gotchas: uncompyle6 fails on 3.9+ -> use pycdc/decompyle3. Extracted entry .pyc often misses magic header — prepend magic from a same-version .pyc before decompiling
- frequency: med
- depth: quick
- sources: https://ctf.support/reverse-engineering/decompilers/, https://medium.com/@0xMr_Robot/nahamcon-ctf-2024-reverse-engineering-challenges-b397296721c1

## ptrace anti-debug bypass (Linux)
- category: rev
- signal: Binary exits/forks weirdly under gdb; decompiler shows ptrace(PTRACE_TRACEME), /proc/self/status TracerPid read, or prctl(PR_SET_DUMPABLE); sometimes in a ctor before main
- technique: Force ptrace return 0 in gdb, LD_PRELOAD a fake ptrace, or patch the conditional jump / NOP the check statically
- tool/command: echo 'long ptrace(int a,int b,void*c,void*d){return 0;}'|gcc -shared -fPIC -xc - -o fp.so; LD_PRELOAD=./fp.so ./bin
# or gdb: catch syscall ptrace; run; set $rax=0; continue
- gotchas: Layered checks (ptrace+TracerPid+rdtsc timing) — one bypass isn't enough. Direct syscall (no libc) defeats LD_PRELOAD -> patch instruction. fork variant ptraces the PARENT
- frequency: med
- depth: deep
- sources: https://ctf-wiki.mahaloz.re/reverse/linux/detect-dbg/, https://ctftime.org/writeup/24049, https://jaybailey216.com/debugging-stripped-binaries/

## Windows IsDebuggerPresent anti-debug patch
- category: rev
- signal: Windows PE; x64dbg/decompiler shows IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, or inline PEB BeingDebugged read; flag gated on result
- technique: Force check to report no debugger: patch the conditional jump or zero the return value so execution falls to the flag branch
- tool/command: # x64dbg: bp IsDebuggerPresent; after call set EAX=0; or patch JNZ->JMP / NOP test. ScyllaHide plugin auto-hides
- gotchas: PEB BeingDebugged read inline (no API) -> set byte at PEB+2 to 0. Multiple layered checks; ScyllaHide covers most at once
- frequency: med
- depth: deep
- sources: https://medium.com/@talal.ak/picoctf-writeups-reverse-engineering-challenges-winantidbgx100-winantidbgx200-winantidbgx300-53548333ec57

## Custom VM / bytecode interpreter
- category: rev
- signal: Decompiler shows big switch/jumptable dispatch over an opcode byte from an embedded array, a pc/ip index, and a register/stack array; angr explodes
- technique: Map each switch case to semantics, write a Python disassembler over the bytecode blob, then read/emulate; lift the flag-check compare to Z3
- tool/command: # Ghidra: dump bytecode array, map each case->mnemonic; python: for i,op in enumerate(prog): print(i,OPS.get(op,op)); feed final compare to z3
- gotchas: Find dispatch (indirect jump on opcode) first. Only RE the ops the flag-check touches. Watch operand widths/endianness. Self-modifying VMs decrypt next handler at runtime — dump bytecode from memory after init. Look for instr-count/timing side channel to brute per byte
- frequency: med
- depth: deep
- sources: https://ctftime.org/writeup/12761, https://gynvael.coldwind.pl/?lang=en&id=763, https://www.kalmarunionen.dk/writeups/2022/midnightsun-quals-revver/readme/

## Hidden/unreachable function force-execute
- category: rev
- signal: Decompiler shows a function (print-flag/decrypt) never called from main; or a 'secret phase' string seen at runtime but absent in static flow
- technique: Force execution: break at main, set RIP/EIP to the hidden function, or patch a call into it. For self-modifying code, dump after decrypt runs
- tool/command: gdb ./bin -ex 'break main' -ex run -ex 'set $rip=0xHIDDEN' -ex continue
- gotchas: Function may need args/this-ptr/stack set up first. Self-XOR-decrypted code only exists after decrypt runs — break AFTER decryption then dump
- frequency: med
- depth: deep
- sources: https://medium.com/@0xMr_Robot/nahamcon-ctf-2024-reverse-engineering-challenges-b397296721c1, https://maulvialf.medium.com/write-up-reverse-engineering-htb-apocalypse-2023-936b87b4726

## WASM to readable form
- category: rev
- signal: .wasm file (\x00asm magic) or web app loading WebAssembly; JS calls exported verify/check
- technique: Convert to C-like with wasm-decompile (more readable than wat); read logic or breakpoint the export in browser DevTools Sources. Flag often a const in data segment
- tool/command: wasm-decompile mod.wasm -o mod.dc; wasm2wat mod.wasm -o mod.wat; strings mod.wasm | grep -i flag
- gotchas: wasm2wat is verbose stack-machine; wasm-decompile/wasm2c far more readable. Flag bytes may be XORed in data segment — decode like XOR pattern. Check the loader .js; DevTools can step wasm + read Module.HEAPU8
- frequency: low
- depth: deep
- sources: https://maulvialf.medium.com/reversing-webassembly-write-up-hackpack-2023-wasm-safe-6ca78e3f4ee3, https://medium.com/tenable-techblog/coding-a-webassembly-ctf-challenge-5560576e9cb7

## Unity IL2CPP dump
- category: rev
- signal: Game/mobile challenge with GameAssembly.dll or libil2cpp.so + global-metadata.dat; native binary, no readable C# but Unity strings
- technique: Restore symbols/types with Il2CppDumper, then load generated header/script.json into Ghidra/IDA to read method names + flag logic
- tool/command: Il2CppDumper GameAssembly.dll global-metadata.dat ./out; load script.json + ghidra_with_struct.py in Ghidra
- gotchas: global-metadata.dat may be XOR-encrypted/header-stripped — fix magic first. Match IL2CPP version or dumper fails. Flag often in TextAsset/JSON in StreamingAssets, not code
- frequency: low
- depth: deep
- sources: https://github.com/Perfare/Il2CppDumper, https://ctf.support/reverse-engineering/games/unity/

## Seeded PRNG / shuffle reversal
- category: rev
- signal: Decompiled checker calls srand(fixed_seed) then rand() to shuffle/XOR input before comparison (Fisher-Yates swap loop)
- technique: Reproduce the exact rand() sequence with the SAME libc (tiny C program, same platform), then invert the shuffle/XOR to recover original
- tool/command: gcc repro.c -o repro  # srand(SEED); for(...) printf("%d\n",rand()%n); then invert swaps in reverse index order in Python
- gotchas: rand() differs across libc/OS — never use Python's random to reproduce C rand. Reverse Fisher-Yates by applying swaps in reverse index order
- frequency: low
- depth: deep
- sources: https://medium.com/@0xMr_Robot/nahamcon-ctf-2024-reverse-engineering-challenges-b397296721c1