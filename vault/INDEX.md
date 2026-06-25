---
title: INDEX
type: note
permalink: ctf-vault/index
---

# CTF Vault — Pattern Index

Grep this first (`grep -i <keyword> INDEX.md`), then open the category file.
Recognition flow: match **signal** → jump to pattern in `<category>.md` → run its command.

## All patterns

| name | category | signal |
|---|---|---|
| Jinja2/Flask SSTI -> RCE | web | User input reflected and evaluated; {{7*7}} renders 49 and {{7*'7'}} -> 7777777 (confirms  |
| Non-Jinja SSTI fingerprint + RCE (Twig/Freemarker/ERB/Thymeleaf) | web | {{7*7}}=49 but Python payloads fail, OR #{7*7}/${7*7}/<%=7*7%> evaluates. Engine-named exc |
| Go text/template SSTI -> arbitrary file read | web | Go stack (x-powered-by: Echo) + reflected param; {{7*7}} does NOT render but {{printf "%s" "x"}}/{{.}} do (. = echo.Context) -> {{.File "/flag.txt"}} reads any path via os.Open (no clamp). CNCC Can-see-cant-have |
| SQLi: auth bypass / UNION / error / blind (+sqlmap) | web | Login or id/search param; single quote -> 500/SQL error; ORDER BY n errors at some n; AND  |
| XSS-bot + Traefik 2.9 ;-injection -> control bot URL -> exfil | web | source-provided; puppeteer bot visits URL; flag in /flag.txt + localStorage; PINNED Traefik 2.9 (`;`->`&` CVE #9164). `/report?id=;url=<Y>` smuggles url= -> bot goes to Y. FAST: `url=javascript:` reads localStorage.flag, POSTs to /api/reports/add, read back text from /api/reports/get (templates/web/xss_bot_traefik_exfil.sh). SLOW: file:// iframe screenshot. In-app exfil, no listener. picoCTF msfroggenerator2. |
| SQLi: second-order UNION via stored username -> CSV report | web | "prepared everywhere" + a report/export whose FILENAME embeds the username -> username interpolated into report query. Register username = `' UNION SELECT ...-- -`, generate report, read injected rows from the CSV. ?order=/ORDER BY is a RED HERRING. picoCTF ORDER ORDER. |
| OS command injection + filter bypass | web | Field wraps a system tool (ping/nslookup/convert/filename/format param); appending ;id / / |
| JWT alg:none / weak secret / RS256->HS256 confusion | web | Cookie/Authorization is 3 base64url dot-separated parts (eyJ...); header decodes to alg HS |
| File upload bypass -> webshell RCE | web | Upload form filtering extension/MIME/magic bytes; uploaded file reachable under a known we |
| LFI/path traversal -> php://filter source read | web | Param loads a file (page=/file=/include=/lang=/template=); ../../../etc/passwd leaks passw |
| Python pickle / insecure deserialization RCE | web | Cookie/param base64-decodes to pickle opcodes (starts \x80, or gAS/gASV in base64), Flask  |
| Stored/Reflected XSS -> admin-bot cookie theft + CSP bypass | web | Challenge has 'admin bot'/'report to admin'/headless visitor; a field reflects HTML/JS. Fl |
| SSRF -> cloud metadata / gopher internal services | web | Param takes a URL/host (url=/uri=/image=/webhook=/fetch=/redirect=); PDF/screenshot/image- |
| Client-side cookie/auth decode bypass | web | Auth state in a base64/JSON cookie or localStorage (role=user, isAdmin, secret_recipe). No |
| GraphQL introspection -> hidden fields | web | Endpoint /graphql or /api/graphql; POST {"query":...} returns data/errors JSON; 'did you m |
| Reverse-proxy ACL path bypass (HAProxy/nginx) | web | Endpoint 403 at proxy but backend route exists; HAProxy/nginx path ACL. (HTB LockTalk CVE- |
| Prototype pollution (Node/Express) -> RCE / auth bypass | web | JSON body merged/cloned server-side (lodash.merge, deep extend, flat.unflatten, query pars |
| LFI -> RCE via PHP filter chain (no file write) | web | Confirmed include() of fully controlled path (php://filter base64 source read works), but  |
| XXE file read / blind OOB exfil / SVG vector | web | Endpoint accepts XML/SOAP/SAML/SVG/DOCX/XLSX, or Content-Type application/xml; or a JSON A |
| PHP object injection / POP chain (incl. phar) | web | unserialize() on user input, or filesystem fn (file_exists/fopen/md5_file) on user-control |
| DOMPurify / mXSS bypass + CSS exfil under CSP | web | User HTML rendered client-side and sanitized (DOMPurify version in JS bundle), or strict C |
| Class/prototype pollution -> SSRF gopher to internal gRPC | web | User JSON merged into object/class attrs (Ruby class.superclass / Python __class__ chain); |
| Race condition (limit overrun / single-packet) | web | Per-user limit reused concurrently: coupon/giftcard redeem, balance transfer, vote, OTP, a |
| WebSocket client-logic bypass | web | Game/score/auth logic runs over WebSocket; client enforces rules the server trusts. picoCT |
| PostgreSQL SQLi -> RCE via lo_export / COPY FROM PROGRAM | web | UNION-capable SQLi on PostgreSQL, superuser, writable data dir. HTB Aurors Archive. |
| PHP wrapper LFI/SSRF via ftp:// bypass | web | file_get_contents on user URL gated by file_exists(); php:// and http:// blocked but FTP a |
| checksec triage first | pwn | Unknown pwn binary, no description; need to pick exploit class |
| BOF offset via cyclic | pwn | Input into fixed stack buffer (gets/read/scanf %s) crashes; RIP/RSP shows 0x6161... ascii; |
| ret2win (overflow into win function) | pwn | No PIE + no canary; gets/read into small stack buffer; unreferenced win()/flag()/give_shel |
| pop rdi gadget for 64-bit args | pwn | 64-bit ROP; must control RDI (1st arg) to call system/puts |
| ret2libc via puts leak (2-stage ROP) | pwn | BOF, NX on, dynamically linked, libc provided, no win; puts/printf in PLT; ASLR on (libc b |
| one_gadget one-shot shell | pwn | You have libc base + single write/call primitive (overwrite __free_hook/__malloc_hook/GOT/ |
| Format string offset discovery + leak | pwn | User input flows into printf(buf) with no format arg; %p echoes hex back; need offset + le |
| Format string write -> GOT overwrite (fmtstr_payload) | pwn | Format string bug + need code exec; Partial/No RELRO (GOT writable); printf called again a |
| Stack canary leak then BOF | pwn | Canary found / 'stack smashing detected'; AND a format string %p or an overread that print |
| PIE bypass: leak rebase / partial overwrite | pwn | PIE enabled, addrs randomized; either can leak a code/stack pointer, or can overwrite low  |
| tcache poisoning -> __free_hook = system | pwn | Heap menu (alloc/free/edit/view); UAF (freed ptr not nulled) or heap overflow lets you edi |
| UAF libc leak via unsorted bin | pwn | Can free a chunk and still read it (UAF/view-after-free); chunk >0x408 or tcache already f |
| Use-after-free dangling ptr overwrite | pwn | Menu uses an index/pointer after free (not NULLed); you can re-alloc same size to reclaim  |
| ret2syscall (static / no libc) | pwn | Statically linked, NX on; ROPgadget finds pop rax/rdi/rsi/rdx + syscall/int 0x80; '/bin/sh |
| Integer overflow / signed length bypass | pwn | Length/index read as signed int, checked (if len<N) then used as size_t in read/memcpy/mal |
| ret2csu (control rdx/rsi, leakless) | pwn | x86_64 ROP, no pop rdx/pop rsi gadget; need 3rd arg (rdx) for read/write; binary has __lib |
| ret2dlresolve (leakless, no PIE) | pwn | No libc leak / unknown libc, NX on, No PIE, Partial/No RELRO; have BOF + writable area (.b |
| SROP (sigreturn-oriented) | pwn | Very limited gadgets (no pop rsi/rdx), but 'syscall; ret' exists and you can set rax=15; l |
| seccomp ORW shellcode / ROP | pwn | prctl/seccomp in imports or 'sandbox' wording; execve blocked; flag is a file; binary runs |
| fastbin dup / double-free | pwn | Double-free allowed, chunk in fastbin range (<=0x80 x64); pre-tcache glibc (2.23) or tcach |
| safe-linking bypass (glibc >=2.32) | pwn | Heap on glibc 2.32+; naive tcache/fastbin poison writes garbage / crashes in _int_malloc;  |
| Off-by-one / poison-null-byte heap overlap | pwn | Heap write overflows by exactly 1 byte (often NULL) past buffer; classic strlen==N then st |
| House of Botcake (2.29+ double-free overlap) | pwn | glibc 2.29+ with tcache double-free key check; need chunk overlap or arbitrary alloc but n |
| struct callback-pointer overwrite | pwn | Struct w/ func-ptr (callback) + name buf, malloc'd back-to-back; unbounded strcpy into one → overwrite adjacent struct's callback w/ win(); point name→.bss so 2nd copy survives. No glibc internals |
| strings/grep instant flag | rev | Any unknown binary pre-analysis; flag may be a literal or password. Very-easy/easy tag, no |
| ltrace strcmp/memcmp leak | rev | Dynamic-linked binary reads input, prints right/wrong; flag not in strings; visible strcmp |
| Ghidra main->compare static triage | rev | Any unknown native binary; first-look triage before choosing a deeper technique |
| gdb breakpoint on comparison (dynamic dump) | rev | strings/ltrace fail (static, stripped PLT, inlined cmp); decompiler shows a compare/branch |
| angr symbolic execution find/avoid | rev | Single deterministic input check, clear Correct/Wrong branch, no heavy loops/crypto/VM; pu |
| angr with preconstrained symbolic stdin | rev | scanf/fgets reads fixed-length input; per-byte validation, path count manageable but plain |
| XOR/add/rol flag deobfuscation | rev | Decompiler shows a loop XOR/add/rol-ing input or a data blob vs a constant or key array, t |
| Z3 constraint-system flag | rev | Decompiler shows many interdependent arithmetic/bitwise equations over flag bytes (sums, p |
| UPX / packed binary unpack | rev | strings mostly gibberish + 'UPX!'/UPX0/UPX1 section names; high entropy (binwalk -E); tiny |
| .NET managed decompile (dnSpy/ILSpy + de4dot) | rev | file says Mono/.Net assembly or PE with CLR header; strings show mscorlib/System; obfuscat |
| Android APK with jadx | rev | .apk/.aab file; mobile app challenge; flag check in Java/Kotlin, native .so, or resources |
| PyInstaller exe / .pyc decompile | rev | .pyc file, or large .exe whose strings contain PyInstaller/_MEI/python3x.dll |
| ptrace anti-debug bypass (Linux) | rev | Binary exits/forks weirdly under gdb; decompiler shows ptrace(PTRACE_TRACEME), /proc/self/ |
| Windows IsDebuggerPresent anti-debug patch | rev | Windows PE; x64dbg/decompiler shows IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQuery |
| Custom VM / bytecode interpreter | rev | Decompiler shows big switch/jumptable dispatch over an opcode byte from an embedded array, |
| Hidden/unreachable function force-execute | rev | Decompiler shows a function (print-flag/decrypt) never called from main; or a 'secret phas |
| WASM to readable form | rev | .wasm file (\x00asm magic) or web app loading WebAssembly; JS calls exported verify/check |
| Unity IL2CPP dump | rev | Game/mobile challenge with GameAssembly.dll or libil2cpp.so + global-metadata.dat; native  |
| Seeded PRNG / shuffle reversal | rev | Decompiled checker calls srand(fixed_seed) then rand() to shuffle/XOR input before compari |
| RSA small e cube root (unpadded) | crypto | e=3 (or small e), single ciphertext, short plaintext, no padding; m^e < n so no modular wr |
| Factor small/known n (FactorDB + RsaCtfTool) | crypto | n < ~512 bits, famous/known number, or only (n,e,c) with no hint. Always try first. |
| Fermat factorization (close primes) | crypto | /p-q/ small — q=nextprime(p), 'primes generated near each other', or n^0.5 near integer; f |
| Shared-factor GCD across moduli | crypto | Multiple RSA public keys given at once; suspect a shared prime between two moduli. |
| RSA common modulus | crypto | Same n, SAME plaintext under two different exponents e1,e2 with gcd(e1,e2)=1; two cipherte |
| Hastad broadcast (same m, >=e moduli) | crypto | Same plaintext to e recipients: e distinct (n_i,c_i) pairs, same small e (usually 3), no/i |
| Wiener / Boneh-Durfee small d | crypto | Very LARGE e (close to n in size) with normal n -> small private d (Wiener d<n^0.25, Boneh |
| Coppersmith univariate (fpylll, NO SAGE) | crypto | small e + known-high-bits-of-msg (stereotyped), OR known top ~half bits of factor p -> factor n. research/crypto/templates/coppersmith_fpylll.py (verified). |
| Biased-nonce (EC)DSA / HNP (fpylll, NO SAGE) | crypto | many (EC)DSA sigs, nonce short or known MSB/LSB bits -> recover key via HNP lattice. sigs ~1.3*nbits/bias. research/crypto/templates/hnp_lattice_fpylll.py (recovers P-256 key, verified). bias<=4 bits needs flatter. |
| AES-ECB byte-at-a-time decryption | crypto | Oracle encrypts your_input // SECRET in ECB (deterministic). 32+ identical input bytes ->  |
| AES-CBC bit-flipping | crypto | CBC, you control ciphertext/IV, no MAC/integrity; want to alter a decrypted field (admin=0 |
| CBC padding oracle | crypto | Server leaks valid vs invalid PKCS7 padding (distinct error/status/timing) on attacker cip |
| Repeating-key XOR / many-time pad | crypto | hex/base64 blob, no crypto structure, uneven entropy, ASCII plaintext expected; OR many ms |
| MT19937 / Python random prediction | crypto | Python random / MT19937 used for keys/tokens; you can read >=624 consecutive 32-bit output |
| ECDSA/DSA nonce reuse (repeated r) | crypto | Two signatures share the same r value (=> same nonce k) under same key, different message  |
| Coppersmith stereotyped / partial-known | crypto | Small e, known prefix/suffix with small unknown chunk (flag{REDACTED}); OR known high/low bits |
| ECDSA biased/short nonce (HNP lattice) | crypto | Many signatures with short/biased k (leading zero bits, LCG-derived, low bits zero) under  |
| RSA decryption oracle blinding | crypto | Server decrypts arbitrary ciphertexts but blacklists the exact target c. RSA is multiplica |
| Hash length extension (secret-prefix MAC) | crypto | MAC=H(secret//msg) with Merkle-Damgard hash (MD5/SHA1/SHA256/512); you know msg+MAC and wa |
| AES-GCM/CTR nonce reuse (forbidden attack) | crypto | Same key+nonce for 2+ messages (CTR/GCM): repeated 12-byte IV across (ct,tag) pairs. |
| Discrete log smooth order (Pohlig-Hellman) | crypto | DLP/DH/ECC where group order (p-1 or curve order) factors into small primes (smooth). Give |
| LCG state/parameter recovery | crypto | Outputs follow X_{n+1}=a*X_n+c mod m (custom or Java 48-bit Random). Several consecutive o |
| Unknown file triage (file/strings/binwalk) | forensics | Any blob, wrong/missing extension, `file` says 'data', or first artifact of the challenge. |
| Metadata / EXIF flag stash | forensics | Image/PDF/doc with no obvious stego; 'look closer'/'who took this'. Quick check before dee |
| PNG/BMP LSB stego (zsteg) | forensics | Lossless image (PNG/BMP), clean exiftool/strings, looks visually normal; hint about 'least |
| steghide extract + stegseek crack | forensics | JPEG/BMP/WAV/AU file, often a password hint; file larger than expected; zsteg finds nothin |
| Carve embedded/appended files (binwalk/foremost) | forensics | File larger than its visible content; binwalk lists archives/images at nonzero offsets; da |
| Polyglot file (treat as 2nd format) | forensics | `file -k` lists conflicting types; xxd shows two magic sigs (PNG 89504E47 at 0 AND %PDF- o |
| Corrupted magic bytes / header repair | forensics | File won't open; `file` says 'data'; pngcheck/unzip errors; hexdump shows wrong/zeroed mag |
| PCAP follow stream + export objects | forensics | .pcap/.pcapng with HTTP/FTP/SMB/SMTP transfers or a downloaded payload; 'find the file/fla |
| USB HID keyboard keystroke recovery | forensics | PCAP of USB/URB_INTERRUPT transfers, no IP traffic, usb.data_len==8 reports; hint about ke |
| Volatility3 OS/profile identification | forensics | .raw/.mem/.vmem/.dmp/.lime, or `file` says 'data' and challenge says memory/RAM dump. OS u |
| Volatility3 process/cmdline/network triage | forensics | Confirmed memory dump. Need the malicious/interesting process, what was run, or a C2 IP. |
| Stegsolve bit-plane / channel sweep | forensics | PNG/BMP where zsteg is inconclusive; visible noise, odd color bands, or hint about 'planes |
| Audio spectrogram / DTMF / Morse | forensics | WAV/MP3/FLAC/OGG, sounds like noise/static/beeps/modem; waveform weird; hint 'listen'/'fre |
| DNS / ICMP tunneling exfiltration | forensics | PCAP with abnormal volume of DNS queries to one domain with long random subdomains, or ICM |
| USB HID mouse movement / draw | forensics | USB PCAP with 4-byte reports (usbhid.data first byte 0x01); keyboard decode yields nothing |
| Volatility3 file/registry extraction | forensics | Flag is in a file that was open in RAM, a registry Run/RecentDocs value, or you need to re |
| Volatility3 mspaint/notepad image recovery | forensics | pstree shows mspaint.exe, notepad.exe or a paint-like process and the flag is reportedly d |
| Volatility3 credentials (hashdump/lsadump) | forensics | Memory challenge asking for a password, user NTLM hash, LSA secret, or autorun persistence |
| Disk image mount + deleted-file recovery (TSK) | forensics | File is .dd/.img/.E01/.vmdk/.vhd or `file` says 'filesystem data'; challenge says deleted/ |
| Windows registry hive analysis | forensics | You have NTUSER.DAT/SYSTEM/SAM/SOFTWARE hives (disk or memory); challenge asks for autorun |
| Encrypted ZIP: crack or known-plaintext (bkcrack) | forensics | Password-protected .zip. Check method: `7z l -slt a.zip` shows ZipCrypto (legacy) vs AES.  |
| QR / barcode in image | forensics | Image contains a full/partial QR/barcode, or stego extraction yields a QR-looking PNG. May |
| EXIF GPS + hidden text-field extraction | osint | Given a photo (.jpg/.png/.tiff) and asked WHERE it was taken or for a hidden flag; image i |
| Reverse image search (Yandex-first rotation) | osint | Image with no useful EXIF but a distinctive landmark, building, signage, architecture, or  |
| Username enumeration / cross-platform pivot | osint | You have a single username/handle/display name and need the person's other accounts, bio,  |
| Wayback Machine for dead/changed pages | osint | Challenge references a URL/file that 404s now, a deleted tweet/post/pastebin, or hints at  |
| Google dorking for documents/leaked files | osint | Challenge points at an org/agency and asks for a specific doc, PDF, config, or exposed fil |
| Email -> Google account enrichment (GHunt/Epieos/holehe) | osint | You recover a target's email (whois, profile, business card), especially @gmail.com, and n |
| crt.sh certificate transparency subdomain discovery | osint | You have a root domain and need hidden/internal subdomains (staging, dev, vpn, admin) not  |
| Passive subdomain enum (subfinder/amass) | osint | Root domain target; need a fast comprehensive subdomain list from many passive sources at  |
| DNS record harvesting (TXT/MX/NS) | osint | You have a domain and need infra clues: mail provider, verification tokens, SPF, nameserve |
| Office/PDF document metadata + embedded media | osint | Given .odt/.docx/.pptx/.pdf and the flag isn't in the visible text |
| Shodan/Censys passive IP & service pivot | osint | You recovered an IP (often decoded from doc/image metadata) or a domain and need open port |
| Signage / license plate / QR as geolocators | osint | Image contains a license plate, street sign, QR code, or business name/phone |
| Specialized public trackers (flight/ship/aircraft/space/wildlife) | osint | Image/clue shows an aircraft tail number (e.g. JA222A), ship name, satellite/space object, |
| WiGLE / cell-tower RF geolocation | osint | Given a WiFi BSSID (MAC) or unusual SSID, or a cell tower ID (MCC/MNC/LAC/CID), and asked  |
| Breach / credential lookup | osint | You have an email or username and the challenge hints at a leaked password, breach, or pas |
| Description/text lead beats coordinates | osint | EXIF GPS points somewhere implausible, but a Description/caption names a town or region |
| Landmark geolocation + Street View confirmation | osint | Photo with no GPS and no reverse-image hit, but has signage/language, architecture, vegeta |
| Social media timeline & geo/encoding pivot | osint | You've reached a target's Twitter/Reddit/Spotify/LinkedIn and need a location, a date, or  |
| Shadow / sun-angle chronolocation | osint | Photo with no GPS but visible shadows, sun position, and a roughly-known location; asked f |
| Landmark + OpenStreetMap/Overpass feature query | osint | Photo with identifiable but unnamed features (church spire, water tower, road junction, tr |
| whois + git history + paste-site identity chain | osint | Domain or org name given; need a person, email, or credential behind it |
| Historical Street View / satellite time machine | osint | Need a feature that no longer exists — old advertisement, demolished building, past signag |
| Blockchain explorer wallet/tx tracing | osint | Challenge supplies a crypto wallet address or transaction hash |
| pyjail: subclasses traversal to RCE | misc | Python eval/exec sandbox, __builtins__ wiped/None, but object expressions allowed; no dire |
| pyjail: builtins via exception/generator/lambda frames | misc | __builtins__ name blocked but you can raise/catch, build a lambda, or a genexpr |
| pyjail: recover builtins from a reachable module | misc | __builtins__ emptied in exec scope but a real module (re, os) is in globals() |
| pyjail: bypass char/keyword/dunder/quote blacklist | misc | Filter rejects '_','__','import','os','system', dots, or quotes before eval |
| encoding chain: identify + peel layers (CyberChef Magic) | misc | Blob that decodes to more encoded text; alternating base64/base32/base85/hex/rot, morse, b |
| zip: ZipCrypto known-plaintext (bkcrack) | misc | Legacy ZipCrypto (NOT AES) zip; zipinfo/unzip -v shows 'ZipCrypto'; >=12 contiguous known  |
| git: recover deleted/dangling commit content | misc | .git directory or repo where flag was committed then deleted/emptied in HEAD |
| audio: spectrogram / DTMF / SSTV / morse | misc | WAV/MP3 with odd sound: buzzing band (spectrogram text), keypad tones (DTMF), warble (SSTV |
| pyjail: file read without exec via help/print | misc | open() reachable but exec/system blocked, or only output channel is help/print |
| pyjail: f-string / str.format globals leak | misc | Challenge prints a value through str.format or f-string with attacker-controlled format fi |
| bash jail: $IFS for space + wildcard filenames | misc | Spaces blocked, or filename chars must not be typed directly |
| esolang: recognize by glyphs, run interpreter | misc | +-<>[]., only = brainfuck; spaces/tabs/newlines only = whitespace; Ook./Malbolge/Piet vari |
| docker: flag in deleted/earlier image layer | misc | docker image tar (docker save) or registry pull; secret rm'd in a later layer |
| QR/barcode: decode, repair, reassemble | misc | QR/barcode image — damaged, inverted, fragmented, missing finder/alignment, or color-chann |
| unicode: zero-width / homoglyph hidden data | misc | Plaintext looks normal but odd length, copy-paste artifacts, or fails string comparison |
| pyjail: audit-hook / no-os sidechannel exec | misc | sys.addaudithook blocks os.system/subprocess/open/import, or builtins gutted but modules p |
| pyjail: no-parens call (decorators / comprehension) | misc | Parentheses '(' banned, or must call without (); spaces may also be banned |
| bash jail: no-alphanumeric command construction | misc | Restricted shell allows only chars like $ ( ) # ! { } < \ ' , — no letters/digits |

## Decision flows

### web
**Reflected-input reflex (do FIRST):** any value you send that comes back in the response (path/param/header) = the #1 injection tell -> probe it within the first 5 min BEFORE grinding traversal/LFI/static/recon: SSTI {{7*7}}/${7*7}/<%=7*7%> (Go/Echo: {{.}} renders but {{7*7}} does NOT -> {{.File "/flag.txt"}} reads any file), then XSS <x>, then SQLi '. Recognition beats grinding (lesson: CNCC SSTI lost to a 90%-session traversal grind).
Curly/dollar braces in output or reflected math renders -> SSTI: {{7*7}}? 49 -> Jinja2 (lipsum.__globals__.os.popen) ; {{7*'7'}}=7777777 confirms Jinja2 vs Twig(49) ; else fingerprint via ${}/#{}/<%= %> + error class -> engine-specific gadget.
Quote breaks page / DB error / ORDER BY errors / SLEEP delays -> SQLi: auth form -> ' OR 1=1-- - ; reflected -> UNION dump ; no output -> boolean/time blind or sqlmap (--ignore-code 401 on login).
Param feeds a system tool / output looks like shell -> command injection: ;id then ${IFS}/brace bypass ; blind -> ;sleep 5 or OOB curl.
Param loads a file (page=/file=) -> LFI: ../../etc/passwd confirms -> php://filter base64 source read -> if include sink & no write, php_filter_chain_generator for RCE.
Param takes a URL/host (url=/webhook=/image=) -> SSRF: 169.254.169.254 metadata -> filter? alt IP encodings / @ / # -> gopher:// for internal Redis/gRPC RCE.
Upload form + web-reachable path -> webshell: alt ext (.phtml) / double ext / magic-byte / .htaccess.
3 base64url dot parts (eyJ...) -> JWT: alg:none -> crack HS secret -> RS256->HS256 confusion with public key.
JSON body merged server-side, __proto__ accepted -> prototype pollution: flip isAdmin -> child_process/EJS gadget for RCE.
base64 cookie/param decodes to \\x80 pickle / rO0 java / O:NN php -> insecure deser: __reduce__ os.system / ysoserial / POP chain.
admin bot / 'report to admin' + reflected HTML -> XSS cookie theft to webhook (HttpOnly -> exfil page DOM; CSP -> location redirect).
Accepts XML/SVG/DOCX or app/xml content-type -> XXE: SYSTEM entity file read -> blind OOB DTD.
403 at proxy but route exists -> proxy ACL bypass (# / %2f / dot-segments).
/graphql endpoint -> introspection dump -> query hidden field.
Per-user limit + concurrency -> race condition (Turbo Intruder single-packet).

### pwn
Deep version: `research/pwn/` — decision-tree.md (full triage), techniques.md (60 techniques), templates/ (10 ready-to-fill scripts). Grep there once a pattern below matches.
START: checksec + file + strings + nm (find win/system/'/bin/sh').

STACK bug (gets/read/scanf into buffer):
- find offset with cyclic.
- No PIE + win() exists -> ret2win (add ret for 16-byte align).
- No win, dynamic, libc given -> ret2libc (puts leak -> system); set RDI via pop rdi.
- Canary found -> leak canary first (fmtstr/overread), replace at offset, then BOF.
- PIE on -> leak code ptr to rebase, or partial low-byte overwrite (brute nibble).
- Static / no libc -> ret2syscall (ROPgadget) ; need rdx & no gadget -> ret2csu ; almost no gadgets -> SROP ; no leak + No PIE + Partial RELRO -> ret2dlresolve.

FORMAT STRING (printf(buf)):
- send AAAA.%p... -> find offset.
- need leak -> %N$p canary/libc/PIE.
- need write -> fmtstr_payload(off,{got:target}) (Partial RELRO; Full RELRO -> retaddr).

HEAP (menu alloc/free/edit/view):
- leak libc: free big chunk into unsorted bin, read fd.
- UAF + ptr not nulled -> reclaim slot / tcache poison fd -> __free_hook=system (+/bin/sh chunk).
- glibc>=2.32 -> mangle fd (safe-linking), need heap leak.
- glibc>=2.34 -> no __free_hook -> FSOP/_IO/stdout.
- double-free blocked by key (2.29+) -> House of Botcake.
- fastbin range + old glibc -> fastbin dup.
- off-by-one null past chunk -> poison-null-byte overlap.

SECCOMP (prctl/seccomp, execve blocked):
- seccomp-tools dump -> ORW shellcode (open/read/write or openat) ; NX -> ROP-to-ORW / setcontext.

PRIMITIVE chosen but limited: libc base + 1 write -> one_gadget (try multiple, check constraints).
Signed length check then size_t use -> integer overflow (send -1).

### rev
REV triage (run in order, cheapest first):
1. `file ./bin` -> identify type. .NET/Mono? -> dnSpy/de4dot. .apk? -> jadx. .wasm? -> wasm-decompile. .pyc/PyInstaller? -> pyinstxtractor+pycdc. ELF/PE native -> continue.
2. `strings -a -n6` + grep flag format (also `strings -el` for UTF-16). Hit -> done.
3. Gibberish strings / UPX0-UPX1 sections / high entropy -> `upx -d` (or dump from memory if magic tampered), restart at step 2.
4. Dynamic-linked + 'right/wrong' prompt -> `ltrace -s200` for strcmp/memcmp leak.
5. ltrace fails (static/stripped/inlined) -> Ghidra main, read decompiler to the compare; gdb breakpoint on cmp, dump $rsi/$rdi.
6. Decompiler shows XOR/add/rol loop vs constant -> extract bytes+key, invert in Python (reverse op order).
7. Single deterministic input check, clear Correct/Wrong branch -> angr find/avoid (constrain length + printable).
8. Many interdependent arithmetic equations over bytes (angr explodes) -> Z3 BitVec(8) per byte + printable bounds.
9. Big switch/dispatch loop over opcode array + pc/stack -> custom VM: lift bytecode, emulate/Z3.
10. Behaves differently under gdb (ptrace/IsDebuggerPresent/TracerPid) -> patch jump / LD_PRELOAD stub / set $rax=0.
11. Hidden func never called from main -> gdb set $rip to it (after any decrypt runs).

### crypto
Deep version: `research/crypto/` — decision-tree.md (triage by what you're handed), techniques.md (76 techniques), templates/ (16 ready-to-fill solvers). Grep there once a pattern below matches. sage NOT installed → lattice/Coppersmith snippets flagged NEEDS SAGE; everything else runs pure-python.

RSA (have n,e,c):
1. n small/known -> factordb -> RsaCtfTool --attack all.
2. Multiple n given -> batch gcd (shared factor).
3. Same n, two e, same m -> common modulus.
4. Same m to many recipients, small e -> Hastad broadcast (CRT + e-th root).
5. e tiny (3) + short msg, no padding -> integer e-th root (try +k*n).
6. e huge (~n) -> Wiener -> Boneh-Durfee.
7. |p-q| small / nextprime hint -> Fermat.
8. Know most of plaintext or partial p bits, small e -> Coppersmith small_roots.
9. Server decrypts but blacklists target c -> blinding (c*r^e).

Block cipher (AES):
- repeated 16B blocks -> ECB -> byte-at-a-time decrypt.
- CBC + control ct, no MAC -> bit-flip target field.
- CBC + valid/invalid padding leak -> padding oracle.
- GCM/CTR same nonce twice -> keystream XOR (recover PT) or forbidden attack (forge tag).

PRNG / tokens:
- Python random / MT19937, >=624 outputs -> randcrack clone; partial bits -> symbolic untwister.
- X_{n+1}=aX+c -> LCG recovery (gcd for m, then a,c); truncated -> lattice.

Signatures:
- two sigs same r -> ECDSA nonce reuse (instant key).
- many sigs, short/biased k -> HNP lattice (LLL).

Hash/MAC:
- MAC=H(secret||msg), Merkle-Damgard -> length extension (hashpump). HMAC -> immune.

DLP/DH/ECC:
- factor(order) smooth -> Pohlig-Hellman (sage discrete_log). Else BSGS/rho or check anomalous curve.

XOR / unknown blob:
- repeating-key -> xortool (keylen via Hamming, freq per column). Many msgs same key -> crib-drag.

### forensics
Always start: `file -k` + `strings`/`exiftool` + `binwalk` on the artifact. Then branch by type: IMAGE (PNG/BMP) -> exiftool/strings -> zsteg -a -> Stegsolve bit-planes -> binwalk carve; IMAGE (JPEG) -> exiftool/strings -> steghide -p '' -> stegseek rockyou -> binwalk; FILE WON'T OPEN / `file` says 'data' -> check magic bytes vs expected, repair header (notrunc dd), check polyglot (`file -k` multi-type -> unzip/pdfdetach); FILE OVERSIZED / extra signature -> binwalk -e / foremost / carve at offset; PCAP -> follow TCP stream + Export Objects -> if USB: keyboard(8B,usb.data_len==8)->usbkeyboard.py / mouse(4B)->plot dx,dy -> if many DNS/ICMP: decode subdomain labels (base32/hex); MEMORY DUMP (.raw/.mem/.vmem/.dmp) -> windows.info -> pstree/psscan/cmdline/netscan/malfind -> filescan|grep flag + dumpfiles -> hashdump/registry.printkey -> mspaint/notepad PID -> memmap dump -> GIMP raw; DISK IMAGE (.dd/.E01) -> mmls -> fls -r -d -> icat by inode / extundelete; AUDIO (wav/mp3) -> steghide -> spectrogram (sox/Audacity) -> multimon-ng DTMF/Morse; ENCRYPTED ZIP -> 7z -slt method check -> ZipCrypto+known-plaintext=bkcrack else zip2john+john; QR fragment -> zbarimg (negate/threshold if it fails).

### osint
Start by classifying the artifact you were handed. IMAGE/PHOTO (most common): exiftool first (GPS + UserComment/Artist/Description) -> if scrubbed, crop to unique feature and reverse-image (Yandex>Lens>Bing) -> if no hit, visual geolocation (signage language, architecture, plates, QR via zbarimg) -> confirm exact spot in Google Street View/Earth -> shadows? SunCalc for time, Overpass for unnamed features. USERNAME/HANDLE: sherlock + whatsmyname -> pivot bios -> social timeline (geotags, base58/64 in bios, acrostics in playlists). EMAIL: holehe/Epieos/GHunt -> Google Maps contributions + public Calendar -> breach lookup (HIBP/dehashed). DOMAIN/ORG: crt.sh + subfinder for subdomains -> dig TXT/MX/NS -> whois -> git commit emails -> recovered IP into Shodan/Censys. DEAD/DELETED URL or historical clue: Wayback (waybackurls) + Google dorks (site:+filetype:). DOCUMENT (.docx/.pdf/.odt): unzip + exiftool the embedded media/thumbnails/metadata. IDENTIFIER (tail number/ship/plate/SSID/wallet): route to its registry — airfleets/FR24, marinetraffic, worldlicenseplates, WiGLE/opencellid, etherscan. Always: GPS and reverse-image are red-herring-prone — reconcile with text leads; many trackers/Street View have a date toggle, use it for the challenge's specified date.

### misc
Misc triage (most common first): (1) Python eval/exec prompt = pyjail -> if you can write objects: subclasses-to-RCE; if __builtins__ named-blocked: frame/lambda/genexpr globals; if a module is in scope: module.__builtins__; if filter on _/__/keywords/quotes: NFKC fullwidth + concat + chr; if str.format/f-string controlled: globals leak; if only open(): print(*open). If audit hook or '(' banned -> sidechannel/no-parens (deep). (2) Restricted shell = bash jail -> spaces/filenames: ${IFS}+globs; only special chars: octal+arithmetic build (deep). (3) Opaque text blob -> CyberChef Magic peel; if glyphs are +-<>[].,/whitespace -> esolang interpreter; if zero-width/homoglyph bytes -> unicode steg (xxd 'e2 80'). (4) Encrypted zip -> zipinfo: ZipCrypto -> bkcrack known-plaintext (AES = stop). (5) .git dir -> log --all/reflog/fsck. (6) docker .tar -> extract layers, grep before .wh whiteout. (7) audio WAV -> spectrogram FIRST, else multimon DTMF/morse, qsstv SSTV. (8) QR image -> zbarimg, else QRazyBox repair + Reed-Solomon.- web: ImageMagick SVG image-upload LFI (text:/caption:@ /flag → rendered thumbnail) — boroCTF Kobeni
- osint: image-as-Brainfuck + X guest-API persona OSINT + boro{}/CTF{REDACTED} format gotcha — boroCTF Satoshi Hunt
- web: Go text/template SSTI — reflected param `{{.}}`→echo.Context, `{{.File "/flag.txt"}}` arbitrary read (os.Open, no clamp) — CNCC Can-see-cant-have
