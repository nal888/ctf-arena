---
title: crypto
type: note
permalink: ctf-vault/crypto
---

# Cryptography — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 20 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## RSA small e cube root (unpadded)
- category: crypto
- signal: e=3 (or small e), single ciphertext, short plaintext, no padding; m^e < n so no modular wrap. c often small vs n.
- technique: c = m^e over the integers; take integer e-th root. If wrapped, brute k: iroot(c+k*n, e).
- tool/command: python3 -c 'from gmpy2 import iroot; from Crypto.Util.number import long_to_bytes as l; import itertools
for k in itertools.count():
 r,ok=iroot(c+k*n,3)
 if ok: print(l(int(r))); break'
- gotchas: Fails under OAEP/PKCS1 padding (root never exact). iroot returns (root,is_exact) — only trust when exact. If many recipients instead, it is Hastad not plain root.
- frequency: high
- depth: quick
- sources: https://book.jorianwoltjer.com/cryptography/asymmetric-encryption/rsa, https://github.com/RsaCtfTool/RsaCtfTool

## Factor small/known n (FactorDB + RsaCtfTool)
- category: crypto
- signal: n < ~512 bits, famous/known number, or only (n,e,c) with no hint. Always try first.
- technique: Look n up in factordb; if absent throw all-attacks tool (fermat, pollard, ecm, roca...).
- tool/command: python3 -c 'from factordb.factordb import FactorDB as F; f=F(n); f.connect(); print(f.get_factor_list())'  ||  RsaCtfTool --publickey key.pub --uncipher c --attack all
- gotchas: FactorDB returns [n] (status C/CF) when it cannot factor — check list length. --attack all can hang; set timeouts. Some attacks need sage/gmpy.
- frequency: high
- depth: quick
- sources: https://picoctfsolutions.com/posts/rsa-attacks-ctf, https://github.com/RsaCtfTool/RsaCtfTool

## Fermat factorization (close primes)
- category: crypto
- signal: |p-q| small — q=nextprime(p), 'primes generated near each other', or n^0.5 near integer; factordb has no answer.
- technique: a=ceil(sqrt(n)), increment until a^2-n is a perfect square b^2; p=a+b, q=a-b.
- tool/command: RsaCtfTool --publickey key.pub --attack fermat --private   # sage: a=isqrt(n)+1\nwhile not is_square(a*a-n): a+=1\nb=isqrt(a*a-n)
- gotchas: Only fast when |p-q| ~ n^0.25 or less; else loops forever. Not ROCA (use --isroca). Try factordb first.
- frequency: high
- depth: quick
- sources: https://github.com/RsaCtfTool/RsaCtfTool, https://book.jorianwoltjer.com/cryptography/asymmetric-encryption/rsa

## Shared-factor GCD across moduli
- category: crypto
- signal: Multiple RSA public keys given at once; suspect a shared prime between two moduli.
- technique: gcd(n_i,n_j) over all pairs — any nontrivial gcd is a shared prime, then d = inverse(e, phi).
- tool/command: RsaCtfTool --publickey "keys/*.pub" --private --attack common_factor   # or python3 -c 'from math import gcd; print(gcd(n1,n2))'
- gotchas: Needs >=2 moduli actually sharing a factor; useless on one well-generated key. Different from common-modulus (same n, two e).
- frequency: high
- depth: quick
- sources: https://github.com/RsaCtfTool/RsaCtfTool

## RSA common modulus
- category: crypto
- signal: Same n, SAME plaintext under two different exponents e1,e2 with gcd(e1,e2)=1; two ciphertexts c1,c2.
- technique: Bezout a*e1+b*e2=1, then m = c1^a * c2^b mod n (invert ciphertext for negative coefficient).
- tool/command: python3 -c 'from egcd import egcd; g,a,b=egcd(e1,e2)
m=(pow(c1,a,n) if a>0 else pow(pow(c1,-1,n),-a,n))*(pow(c2,b,n) if b>0 else pow(pow(c2,-1,n),-b,n))%n; print(m)'
- gotchas: Needs gcd(e1,e2)=1 AND same m AND same n. Negative Bezout coeff -> invert that ciphertext first.
- frequency: high
- depth: quick
- sources: https://ctf-wiki.mahaloz.re/crypto/asymmetric/rsa/rsa_module_attack/, https://github.com/RsaCtfTool/RsaCtfTool

## Hastad broadcast (same m, >=e moduli)
- category: crypto
- signal: Same plaintext to e recipients: e distinct (n_i,c_i) pairs, same small e (usually 3), no/identical padding.
- technique: CRT-combine c_i over the n_i to get m^e mod prod(n_i); since m^e < prod, take integer e-th root.
- tool/command: sage: x=crt([c1,c2,c3],[n1,n2,n3]); from gmpy2 import iroot; print(iroot(int(x),3))   # or RsaCtfTool --attack hastad
- gotchas: Need >=e ciphertexts, pairwise-coprime n. If per-recipient padding differs use Hastad+Coppersmith, not plain CRT.
- frequency: high
- depth: quick
- sources: https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Hastad-Broadcast/README.md, https://docs.xanhacks.xyz/crypto/rsa/08-hastad-broadcast-attack/

## Wiener / Boneh-Durfee small d
- category: crypto
- signal: Very LARGE e (close to n in size) with normal n -> small private d (Wiener d<n^0.25, Boneh-Durfee d<n^0.292).
- technique: Continued-fraction convergents of e/n recover d (Wiener); lattice reduction for the larger Boneh-Durfee bound.
- tool/command: `python3 -c 'import owiener; d=owiener.attack(e,n); print(d, pow(c,d,n))'`  ||  Boneh-Durfee (NO SAGE NEEDED) `research/crypto/templates/boneh_durfee_fpylll.py` (fpylll, self-checks; works to d<n^0.28; near 0.292 needs flatter)  ||  `RsaCtfTool --attack boneh_durfee,partial_q`
- gotchas: Trigger is huge e, NOT small e (3/65537). Wiener fails past n^0.25 -> escalate to Boneh-Durfee. Confirm by testing recovered d.
- frequency: high
- depth: quick
- sources: research/crypto/lattice-fpylll-status.md ; https://github.com/RsaCtfTool/RsaCtfTool

## Coppersmith (univariate) — fpylll, NO SAGE
- category: crypto
- signal: (a) small e (3/5/17) + message is known_prefix*2^k + small_unknown (stereotyped / known-high-bits-of-msg); or (b) you know the top ~half bits of a factor p (partial key exposure → factor n).
- technique: Howgrave-Graham lattice + LLL (hand-rolled, fpylll). (a) f(x)=(known+x)^e - C mod n, root = unknown. (b) f(x)=p_high+x, root mod p; gcd(f(root),n) factors n.
- tool/command: `research/crypto/templates/coppersmith_fpylll.py` (both cases self-verified; ~45% of p's bits recoverable, theory limit 50%).
- gotchas: NOT sage — works with fpylll on this box. `int(N**beta)` overflows → use gmpy2.iroot on rational β; root-find with sympy `Poly.ground_roots()` not `sympy.roots()`; divisor test = nontrivial gcd>1.
- frequency: med-high
- sources: research/crypto/lattice-fpylll-status.md

## Biased-nonce (EC)DSA / Hidden Number Problem — fpylll, NO SAGE
- category: crypto
- signal: MANY (EC)DSA signatures (r,s,z) under ONE key, with the nonce k short or sharing known MSBs/LSBs (or "k is small"). HNP also = any "recover secret from many noisy linear-mod-n samples".
- technique: HNP lattice (Boneh-Venkatesan embedding) + LLL — k_i = a_i + t_i*d mod n, build (m+2)x(m+1) basis, shortest vector reveals the nonces → d. Curve-agnostic (DSA: use subgroup order q). Two sigs same r = nonce reuse, pure algebra instead.
- tool/command: `research/crypto/templates/hnp_lattice_fpylll.py` (self-test recovers a P-256 key; short/MSB/LSB variants). Reuse: `research/crypto/templates/ecdsa_nonce.py`.
- gotchas: sigs needed ≈ 1.3*(nbits/bias_bits). **bias ≤ 4 bits is genuinely hard** (needs flatter/BKZ≥40). fpylll IntegerMatrix rejects gmpy2.mpz → cast to int; carry d implicitly via the t-row (not its own coord).
- frequency: med (recurring in hard CTF crypto)
- sources: research/crypto/lattice-fpylll-status.md ; Surin&Cohney eprint 2023/032 ; ur4ndom.dev practical-lattice

## AES-ECB byte-at-a-time decryption
- category: crypto
- signal: Oracle encrypts your_input || SECRET in ECB (deterministic). 32+ identical input bytes -> repeated 16B ciphertext blocks.
- technique: Align so one unknown byte sits at block boundary; brute 0-255 matching that block; shift one byte left per recovered byte.
- tool/command: # detect: enc('A'*48) has repeated 16B block. Then:
pad=b'A'*(15-i%16); tgt=enc(pad)[blk]
for g in range(256):
 if enc(pad+known+bytes([g]))[blk]==tgt: known+=bytes([g])
- gotchas: Random prefix needs length calibration (find boundary via duplicate blocks). Must be ECB not CBC. Tail PKCS7 can false-read last byte.
- frequency: high
- depth: quick
- sources: https://book.jorianwoltjer.com/cryptography/aes, https://github.com/onealmond/hacking-lab/blob/master/cryptohack/ecb-oracle/writeup.md

## AES-CBC bit-flipping
- category: crypto
- signal: CBC, you control ciphertext/IV, no MAC/integrity; want to alter a decrypted field (admin=0 -> admin=1).
- technique: Flip byte j in block C[i-1] -> same byte flips in P[i]: C[i-1][j]^=cur^want. Block i-1 becomes garbage. Use IV for block 0.
- tool/command: python3 -c 'ct=bytearray(ct); ct[16*(i-1)+j]^=ord(cur)^ord(want)'
- gotchas: Preceding block is sacrificed (garbled) — ensure it is throwaway/IV. Off-by-one on block index is the usual bug. Fails if MAC/AEAD checked.
- frequency: high
- depth: quick
- sources: https://book.jorianwoltjer.com/cryptography/aes, https://ctf-wiki.mahaloz.re/crypto/blockcipher/mode/cbc/

## CBC padding oracle
- category: crypto
- signal: Server leaks valid vs invalid PKCS7 padding (distinct error/status/timing) on attacker ciphertext.
- technique: Per byte right-to-left: forge prev block to force valid padding -> intermediate=guess^padlen; plaintext=intermediate^realprev. Block by block.
- tool/command: padbuster URL <b64_ct> 16 -encoding 0   # or python -m padding_oracle / sciencemanx solver
- gotchas: Last-byte false positive when real pad already 0x02 0x02 — verify by tweaking 2nd-to-last byte. Match block size and encoding flag (0=b64). Need IV for block 0.
- frequency: high
- depth: quick
- sources: https://ctf-wiki.mahaloz.re/crypto/blockcipher/mode/padding-oracle-attack/, https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/

## Repeating-key XOR / many-time pad
- category: crypto
- signal: hex/base64 blob, no crypto structure, uneven entropy, ASCII plaintext expected; OR many msgs under same keystream.
- technique: Find keylen via Hamming/IoC, split columns, single-byte freq-attack each. Many-time pad: crib-drag known words across c_i^c_j.
- tool/command: xortool ciphertext.bin -c 20   # then xortool-xor; crib: xortool -b -p 'flag{' file.enc
- gotchas: -c is most-common plaintext byte (often space 0x20). Wrong keylen -> garbage; try top 2-3. Short ct makes column stats unreliable -> crib-drag.
- frequency: high
- depth: quick
- sources: https://github.com/hellman/xortool, http://travisdazell.blogspot.com/2012/11/many-time-pad-attack-crib-drag.html

## MT19937 / Python random prediction
- category: crypto
- signal: Python random / MT19937 used for keys/tokens; you can read >=624 consecutive 32-bit outputs (or fewer/truncated).
- technique: Feed 624 outputs to clone full state, predict all future (and past). Truncated/partial bits -> Z3 symbolic untwister.
- tool/command: from randcrack import RandCrack; rc=RandCrack(); [rc.submit(x) for x in outs624]; rc.predict_getrandbits(32)   # partial: symbolic_mersenne_cracker Untwister
- gotchas: Need exactly 624 full 32-bit consecutive words; getrandbits(>32) splits into multiple words. random.random() drops bits -> symbolic. seed(time) -> brute seed. Not for os.urandom/secrets.
- frequency: high
- depth: quick
- sources: https://github.com/kmyk/mersenne-twister-predictor, https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng

## ECDSA/DSA nonce reuse (repeated r)
- category: crypto
- signal: Two signatures share the same r value (=> same nonce k) under same key, different message hashes z1,z2.
- technique: k=(z1-z2)/(s1-s2) mod n; then d=(s1*k - z1)*r^-1 mod n. Two sigs suffice.
- tool/command: python3 -c 'k=((z1-z2)*pow(s1-s2,-1,n))%n; d=((s1*k-z1)*pow(r,-1,n))%n; print(d)'   # lib: tintinweb/ecdsa-private-key-recovery
- gotchas: Same r is the giveaway, not same s. z must be hash truncated to curve bit length (leftmost bits). Try +/- s sign ambiguity.
- frequency: high
- depth: quick
- sources: https://github.com/tintinweb/ecdsa-private-key-recovery, https://7rocky.github.io/en/ctf/other/ctfzone/come-on-feel-the-nonce/

## Coppersmith stereotyped / partial-known
- category: crypto
- signal: Small e, known prefix/suffix with small unknown chunk (flag{REDACTED}); OR known high/low bits of prime p. Unknown < n^(1/e).
- technique: f(x)=(known+x)^e - c over Zmod(n), small_roots() via LLL. Partial p: f(x)=p_high+x, beta=0.5.
- tool/command: sage: P.<x>=PolynomialRing(Zmod(n)); f=(m_known+x)^e - c; f=f.monic(); print(f.small_roots(X=2^kbits, beta=1, epsilon=0.05))
- gotchas: Unknown region MUST be < n^(1/e) else returns []. Poly must be monic(). Tune X/epsilon. Needs SageMath; LLL slow for large X.
- frequency: high
- depth: deep
- sources: https://nightxade.github.io/ctf-writeups/writeups/2024/squ1rrel-CTF-2024/crypto/partial-rsa.html, https://github.com/mimoo/RSA-and-LLL-attacks

## ECDSA biased/short nonce (HNP lattice)
- category: crypto
- signal: Many signatures with short/biased k (leading zero bits, LCG-derived, low bits zero) under same key.
- technique: Build CVP/SVP lattice over the signatures; LLL/BKZ recovers d (hidden number problem).
- tool/command: git clone https://github.com/daedalus/BreakingECDSAwithLLL; sage lattice script (scale by 2^bias)
- gotchas: Need ~ n_bits/leaked_bits signatures and correct lattice scaling; off-by-one in bias size makes LLL miss. Use right hash truncation.
- frequency: high
- depth: deep
- sources: https://github.com/daedalus/BreakingECDSAwithLLL, https://blog.cryptohack.org/ecdsa-side-channel-attack-projective-signatures-donjon-ctf-writeup

## RSA decryption oracle blinding
- category: crypto
- signal: Server decrypts arbitrary ciphertexts but blacklists the exact target c. RSA is multiplicatively homomorphic.
- technique: Send c'=c*r^e mod n; oracle returns m*r; multiply by r^-1 mod n to recover m.
- tool/command: python3 -c 'r=2; cc=(c*pow(r,e,n))%n; mm=oracle(cc); print((mm*pow(r,-1,n))%n)'
- gotchas: Oracle may return truncated bytes not full int — use small r. Some oracles strip padding; account for it.
- frequency: med
- depth: quick
- sources: https://picoctfsolutions.com/posts/rsa-attacks-ctf

## Hash length extension (secret-prefix MAC)
- category: crypto
- signal: MAC=H(secret||msg) with Merkle-Damgard hash (MD5/SHA1/SHA256/512); you know msg+MAC and want to append data.
- technique: Resume hash from known digest, append glue padding + your data; produces valid MAC for secret||msg||pad||append.
- tool/command: hashpump -s <mac> -d 'orig_msg' -a '&admin=1' -k <keylen>   # or hash_extender --format sha256; loop keylen 1..64
- gotchas: Does NOT work on HMAC, SHA3, BLAKE2. Brute keylen if unknown. Output contains raw glue bytes — URL/percent-encode exactly.
- frequency: med
- depth: quick
- sources: https://github.com/iagox86/hash_extender, https://en.wikipedia.org/wiki/Length_extension_attack

## AES-GCM/CTR nonce reuse (forbidden attack)
- category: crypto
- signal: Same key+nonce for 2+ messages (CTR/GCM): repeated 12-byte IV across (ct,tag) pairs.
- technique: Keystream repeats: c1^c2=p1^p2 (recover PT with one known). GCM forgery: poly over GF(2^128) from two (C,T) pairs, roots=auth key H, then forge tags.
- tool/command: python3 -c 'print(bytes(a^b for a,b in zip(c1,c2)))'   # forgery: git clone github.com/nonce-disrespect/nonce-disrespect
- gotchas: XOR only gives p1^p2 (needs crib/known msg). Forgery needs GF(2^128) math with reflected bit/byte ordering; multiple H roots -> test each. Strip 16B tag before XOR.
- frequency: med
- depth: deep
- sources: https://www.elttam.com/blog/key-recovery-attacks-on-gcm, https://github.com/ashutosh1206/Crypton/blob/master/Authenticated-Encryption/AES-GCM/Attack-Forbidden/README.md

## Discrete log smooth order (Pohlig-Hellman)
- category: crypto
- signal: DLP/DH/ECC where group order (p-1 or curve order) factors into small primes (smooth). Given g, h=g^x, find x.
- technique: Solve DLP in each small prime-power subgroup, CRT-combine. Sage discrete_log auto-uses PH.
- tool/command: sage: factor(p-1)  # confirm smooth
sage: x=discrete_log(Mod(h,p),Mod(g,p))   # ECC: G(h).log(G(g))
- gotchas: Only fast if order smooth — check factor(order). One large prime factor -> falls back to BSGS/rho (slow). ECC: watch anomalous/singular curves (Smart/MOV).
- frequency: med
- depth: deep
- sources: https://ctf-wiki.mahaloz.re/crypto/asymmetric/discrete-log/discrete-log/, https://blog.cryptohack.org/cryptoctf2021-hard

## LCG state/parameter recovery
- category: crypto
- signal: Outputs follow X_{n+1}=a*X_n+c mod m (custom or Java 48-bit Random). Several consecutive outputs, maybe truncated.
- technique: Known params: invert. Unknown: m=gcd of |t_i*t_{i+2}-t_{i+1}^2|, then a=(s2-s1)/(s1-s0) mod m, c=s1-a*s0. Truncated -> LLL/Z3.
- tool/command: python3 -c 'from math import gcd; from functools import reduce
t=[s[i+1]-s[i] for i in range(len(s)-1)]
m=reduce(gcd,[abs(t[i+2]*t[i]-t[i+1]**2) for i in range(len(t)-2)])
a=((s[2]-s[1])*pow(s[1]-s[0],-1,m))%m; print(m,a)'
- gotchas: Need ~6 outputs for unknown params. Java seed 48-bit + truncated high bits -> use lattice/Z3 not naive algebra. Recover m first.
- frequency: med
- depth: deep
- sources: https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng, https://github.com/deut-erium/RNGeesus