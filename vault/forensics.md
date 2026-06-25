---
title: forensics
type: note
permalink: ctf-vault/forensics
---

# Forensics — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 22 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## Unknown file triage (file/strings/binwalk)
- category: forensics
- signal: Any blob, wrong/missing extension, `file` says 'data', or first artifact of the challenge. Always step 1.
- technique: Identify true type by magic, pull ASCII + UTF-16LE strings, scan for embedded/appended files in one pass before deep work.
- tool/command: file -k blob; xxd -l 64 blob; strings -n8 blob | grep -iE 'flag|ctf\{'; strings -el blob | grep -i flag; binwalk blob
- gotchas: strings -el catches UTF-16LE Windows artifacts that plain strings misses. file -k lists ALL magic matches (polyglot hint).
- frequency: high
- depth: quick
- sources: https://ctf.support/forensics/file-analysis/, https://trailofbits.github.io/ctf/forensics/

## Metadata / EXIF flag stash
- category: forensics
- signal: Image/PDF/doc with no obvious stego; 'look closer'/'who took this'. Quick check before deeper work.
- technique: Flags hide in EXIF Comment/Artist/Creator/GPS/XMP or custom tags. Dump everything.
- tool/command: exiftool -a -u -g1 file.*; exiftool file.* | grep -iE 'comment|flag|author|gps'
- gotchas: Combine with strings; some flags are GPS coords or split across multiple tags.
- frequency: high
- depth: quick
- sources: https://www.neerajlovecyber.com/steganography-cheatsheet-for-ctf-beginners, https://ctf.support/forensics/file-analysis/

## PNG/BMP LSB stego (zsteg)
- category: forensics
- signal: Lossless image (PNG/BMP), clean exiftool/strings, looks visually normal; hint about 'least significant bit'/'pixels'.
- technique: zsteg brute-forces LSB across channels, bit orders and planes. Run default then -a (all combos); look for PK/ZIP/text in output.
- tool/command: zsteg -a image.png   # extract specific channel: zsteg -E 'b1,rgb,lsb,xy' image.png > out.bin
- gotchas: zsteg only works on PNG/BMP (lossless). JPEG => use steghide instead. If zsteg misses, pivot to Stegsolve for non-standard layouts.
- frequency: high
- depth: quick
- sources: https://ctf.support/steganography/image-steganography/, https://csyclub-iiitk.gitbook.io/ctf-guide/forensics/steganography

## steghide extract + stegseek crack
- category: forensics
- signal: JPEG/BMP/WAV/AU file, often a password hint; file larger than expected; zsteg finds nothing (JPEG).
- technique: steghide hides in DCT coeffs with a passphrase. Try empty pass first, then crack with stegseek vs rockyou (millions/sec, far faster than stegcracker).
- tool/command: steghide extract -sf image.jpg -p ''; stegseek image.jpg /usr/share/wordlists/rockyou.txt
- gotchas: Passphrase is often the image name, blank, or a word from the challenge text. stegseek auto-extracts on crack.
- frequency: high
- depth: quick
- sources: https://ctf.support/steganography/image-steganography/, https://ctftime.org/writeup/21627

## Carve embedded/appended files (binwalk/foremost)
- category: forensics
- signal: File larger than its visible content; binwalk lists archives/images at nonzero offsets; data after image/PDF EOF.
- technique: Carve concatenated/embedded files by signature. binwalk for general, foremost for raw blobs, dd for a known offset.
- tool/command: binwalk -e file.bin    # if blocked: binwalk --dd='.*' file.bin   OR  foremost -i file.bin -o out/   OR  dd if=f of=part.zip bs=1 skip=<offset>
- gotchas: binwalk -e sometimes refuses; --dd='.*' forces extraction. Always run on EVERY forensics file even if it looks clean.
- frequency: high
- depth: quick
- sources: https://ctf.support/forensics/file-carving-recovery/, https://github.com/brootware/CTF-Writeups/blob/master/Forensics/binwalk.md

## Polyglot file (treat as 2nd format)
- category: forensics
- signal: `file -k` lists conflicting types; xxd shows two magic sigs (PNG 89504E47 at 0 AND %PDF- or PK zip trailer later). Opens as image but `unzip` lists entries.
- technique: File is valid in two formats at once. Open it directly with the second format's tool to extract the hidden payload. Common pairs: JPG+ZIP, PNG+PDF, PDF+ZIP.
- tool/command: unzip file.jpg; pdftotext file.pdf out.txt; pdfdetach -saveall file.pdf; peepdf file.pdf
- gotchas: ZIP central directory is at file END, so unzip works even when binwalk offset carving is messy. Just rename and open.
- frequency: high
- depth: quick
- sources: https://picoctfsolutions.com/picoctf-2024-secret-of-the-polyglot, https://ctf.support/forensics/file-analysis/

## Corrupted magic bytes / header repair
- category: forensics
- signal: File won't open; `file` says 'data'; pngcheck/unzip errors; hexdump shows wrong/zeroed magic; name mentions 'corrupted'/'broken'.
- technique: Overwrite first bytes with correct signature (notrunc), then validate. For PNG also fix IHDR; brute width/height vs stored CRC if dimensions zeroed.
- tool/command: printf '\x89PNG\r\n\x1a\n' | dd of=corrupt.png bs=1 count=8 conv=notrunc; pngcheck -v corrupt.png
- gotchas: PNG sig is 89 50 4E 47 0D 0A 1A 0A (note 0D0A, not 0A). JPEG=FF D8 FF E0. pngcheck pinpoints the broken chunk/CRC. Flag often hidden in cropped height.
- frequency: high
- depth: quick
- sources: https://dev.to/rudycandy/corrupted-file-picoctf-writeup-446c, https://ctf-wiki.mahaloz.re/misc/picture/png/

## PCAP follow stream + export objects
- category: forensics
- signal: .pcap/.pcapng with HTTP/FTP/SMB/SMTP transfers or a downloaded payload; 'find the file/flag in traffic'.
- technique: Reassemble TCP session to read plaintext creds/flags; export transferred objects to recover files; carve raw streams if no clean object.
- tool/command: tshark -r cap.pcap -z follow,tcp,ascii,0; tshark -r cap.pcap --export-objects http,out/; foremost -i cap.pcap -o carved/   # GUI: Follow>TCP Stream, File>Export Objects
- gotchas: Export Objects also supports SMB/FTP/IMF. If data is gzip'd HTTP, export decompresses it. strings the carved files too.
- frequency: high
- depth: quick
- sources: https://ctf.support/forensics/network-forensics/, https://res260.medium.com/usb-pcap-forensics-barcode-scanner-nsec-ctf-2021-writeup-part-1-3-b0a5392c9313

## USB HID keyboard keystroke recovery
- category: forensics
- signal: PCAP of USB/URB_INTERRUPT transfers, no IP traffic, usb.data_len==8 reports; hint about keyboard/ducky/typed password/keylogger.
- technique: 8-byte HID report = [modifier][reserved][keycode]x6. Extract reports, drop all-zero, map byte[2] via HID usage table, byte[0] 0x02/0x20 = shift.
- tool/command: tshark -r usb.pcap -Y 'usb.data_len==8' -T fields -e usb.capdata > hid.txt; python3 usbkeyboard.py hid.txt   # TeamRocketIst/ctf-usb-keyboard-parser
- gotchas: Field is usb.capdata or usbhid.data depending on capture. Use the parser repo rather than hand-mapping. 4-byte reports => mouse, not keyboard.
- frequency: high
- depth: quick
- sources: https://github.com/TeamRocketIst/ctf-usb-keyboard-parser, https://book.hacktricks.wiki/en/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/usb-keystrokes.html

## Volatility3 OS/profile identification
- category: forensics
- signal: .raw/.mem/.vmem/.dmp/.lime, or `file` says 'data' and challenge says memory/RAM dump. OS unknown.
- technique: Always confirm OS/arch before anything else. vol3 auto-detects so skip imageinfo; Linux needs a matching ISF symbol table built from the debug kernel banner.
- tool/command: vol -f mem.raw windows.info    # Linux: vol -f mem.raw banner
- gotchas: If windows.* plugins all error, it's a Linux/Mac dump — grab banner, build/download the matching ISF symbols.
- frequency: high
- depth: quick
- sources: https://ctf.support/forensics/memory-forensics/, https://xbpt.gitlab.io/ctf/volatility3-cheatsheet.html

## Volatility3 process/cmdline/network triage
- category: forensics
- signal: Confirmed memory dump. Need the malicious/interesting process, what was run, or a C2 IP.
- technique: pslist=linked list, psscan=carved (finds hidden/terminated), pstree=parent-child. Pull cmdline for full invocation, netscan for connections, malfind for injection.
- tool/command: vol -f mem.raw windows.pstree; vol -f mem.raw windows.psscan; vol -f mem.raw windows.cmdline; vol -f mem.raw windows.netscan; vol -f mem.raw windows.malfind
- gotchas: psscan reveals processes hidden from pslist. cmdline often holds the flag (powershell -enc base64, URLs).
- frequency: high
- depth: quick
- sources: https://xbpt.gitlab.io/ctf/volatility3-cheatsheet.html, https://book.jorianwoltjer.com/forensics/memory-dumps-volatility

## Stegsolve bit-plane / channel sweep
- category: forensics
- signal: PNG/BMP where zsteg is inconclusive; visible noise, odd color bands, or hint about 'planes'/'layers'/'XOR'. QR fragments split across planes.
- technique: Step through individual R/G/B/alpha bit planes; flag often appears as text/QR in one plane. Use Data Extract for custom bit/channel order; Image Combiner to XOR two images.
- tool/command: java -jar Stegsolve.jar   # arrow through planes 0..7; Analyse > Data Extract; Image Combiner for XOR. Web alt: Aperi'Solve
- gotchas: Aperi'Solve runs zsteg+stegsolve+strings in one batch web pass — fast triage when no GUI.
- frequency: med
- depth: quick
- sources: https://www.neerajlovecyber.com/steganography-cheatsheet-for-ctf-beginners, https://github.com/DominicBreuker/stego-toolkit

## Audio spectrogram / DTMF / Morse
- category: forensics
- signal: WAV/MP3/FLAC/OGG, sounds like noise/static/beeps/modem; waveform weird; hint 'listen'/'frequency'/'see the sound'. strings/steghide empty.
- technique: Flag drawn as text in the frequency spectrum, or encoded as DTMF/Morse tones. View spectrogram; decode tone pairs for DTMF.
- tool/command: sox audio.wav -n spectrogram -o spec.png   # GUI: Audacity track>Spectrogram, or sonic-visualiser. DTMF/Morse: multimon-ng -t wav -a DTMF -a MORSE_CW audio.wav
- gotchas: Also run steghide on WAV/AU first. Stereo channels may differ — check both. Low-freq text needs zoomed axis.
- frequency: med
- depth: quick
- sources: https://ediscoverychannel.com/2024/01/22/shaking-the-cobwebs-ctf-part-one-audio-analysis/, https://github.com/DominicBreuker/stego-toolkit

## DNS / ICMP tunneling exfiltration
- category: forensics
- signal: PCAP with abnormal volume of DNS queries to one domain with long random subdomains, or ICMP echo packets carrying payloads. Little normal web traffic.
- technique: Data is exfil'd in DNS subdomain labels or ICMP data fields; concatenate the labels/payloads and decode (often hex/base32/base64).
- tool/command: tshark -r cap.pcap -T fields -e dns.qry.name | sort -u; tshark -r cap.pcap -Y icmp -T fields -e data | xxd -r -p
- gotchas: DNS labels often base32 (case-insensitive) not base64. Strip the domain suffix before decoding; preserve query order via frame number.
- frequency: med
- depth: quick
- sources: https://ctf.support/forensics/network-forensics/, https://book.jorianwoltjer.com/forensics/memory-dumps-volatility

## USB HID mouse movement / draw
- category: forensics
- signal: USB PCAP with 4-byte reports (usbhid.data first byte 0x01); keyboard decode yields nothing.
- technique: 4-byte mouse report = [buttons][dx signed][dy signed][wheel]. Accumulate dx/dy while button held and plot to reveal a drawing that spells the flag.
- tool/command: tshark -r f.pcap -Y 'usbhid.data' -T fields -e usbhid.data > mouse.txt   # then plot cumulative dx/dy in python/matplotlib, filter button-down byte 0x01
- gotchas: dx/dy are signed bytes (>0x7f = negative). Only plot points while a button is pressed, else you get continuous scribble.
- frequency: med
- depth: quick
- sources: https://ctf-wiki.mahaloz.re/misc/traffic/protocols/USB/, https://ctf.support/forensics/network-forensics/

## Volatility3 file/registry extraction
- category: forensics
- signal: Flag is in a file that was open in RAM, a registry Run/RecentDocs value, or you need to recover a screenshot/document. filescan shows an interesting path.
- technique: filescan to locate the object offset, dumpfiles by --virtaddr/--physaddr/--pid to recover it. registry.hivelist then printkey to read keys.
- tool/command: vol -f mem.raw windows.filescan | grep -i flag; vol -f mem.raw -o out/ windows.dumpfiles --virtaddr 0x<offset>; vol -f mem.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
- gotchas: Try both --virtaddr and --physaddr if one yields empty. Also brute the raw dump: strings -el mem.raw | grep -i 'CTF{'.
- frequency: high
- depth: deep
- sources: https://book.jorianwoltjer.com/forensics/memory-dumps-volatility, https://ctf.support/forensics/memory-forensics/

## Volatility3 mspaint/notepad image recovery
- category: forensics
- signal: pstree shows mspaint.exe, notepad.exe or a paint-like process and the flag is reportedly drawn/typed but no file on disk.
- technique: Dump the process memory, carve the bitmap. For mspaint, import raw RGB into GIMP and sweep the width until the drawing resolves.
- tool/command: vol -f mem.raw windows.memmap --pid <PID> --dump   # then GIMP: Open as Raw Data, RGB, sweep Width 100-2000 until the flag drawing aligns
- gotchas: Image is often rotated/flipped or RGBA vs RGB — try both and vary width. notepad text may need strings -el on the dump instead.
- frequency: med
- depth: deep
- sources: https://book.jorianwoltjer.com/forensics/memory-dumps-volatility, https://medium.com/@chaoskist/cyberspacectf-2024-memory-forensic-challenge-35d1ea05ea33

## Volatility3 credentials (hashdump/lsadump)
- category: forensics
- signal: Memory challenge asking for a password, user NTLM hash, LSA secret, or autorun persistence.
- technique: Dump NTLM hashes to crack offline, dump LSA secrets, or read Run keys for persistence.
- tool/command: vol -f mem.raw windows.hashdump; vol -f mem.raw windows.lsadump; vol -f mem.raw windows.cachedump
- gotchas: Feed hashdump NTLM into hashcat -m 1000 or john --format=nt with rockyou.
- frequency: med
- depth: deep
- sources: https://xbpt.gitlab.io/ctf/volatility3-cheatsheet.html, https://ctf.support/forensics/memory-forensics/

## Disk image mount + deleted-file recovery (TSK)
- category: forensics
- signal: File is .dd/.img/.E01/.vmdk/.vhd or `file` says 'filesystem data'; challenge says deleted/hidden file; mount shows nothing relevant.
- technique: Mount read-only to browse; or Sleuth Kit: mmls for partitions, fls -r -d to list deleted entries, icat to read data blocks by inode even if the dir entry is gone.
- tool/command: mmls disk.dd; fls -r -d -o <part_offset> disk.dd | grep -i flag; icat -o <part_offset> disk.dd <inode> > recovered; extundelete disk.dd --restore-all
- gotchas: E01 needs ewfmount disk.E01 /mnt then mount the ewf1. Use the partition offset from mmls in fls/icat -o. photorec for FAT/exFAT undelete.
- frequency: med
- depth: deep
- sources: https://www.sleuthkit.org/sleuthkit/desc.php, https://0x90r00t.com/2024/09/30/defcamp-quals-2024-forensics-forensics-disk-write-up/

## Windows registry hive analysis
- category: forensics
- signal: You have NTUSER.DAT/SYSTEM/SAM/SOFTWARE hives (disk or memory); challenge asks for autoruns, recent docs, USB history, or creds.
- technique: RegRipper for automated artifact plugins; hivexsh/reglookup for manual browsing. Key spots: Run keys (persistence), USBSTOR (devices), RecentDocs, UserAssist.
- tool/command: rip.pl -r NTUSER.DAT -f ntuser; reglookup NTUSER.DAT | grep -i run; hivexsh SYSTEM
- gotchas: SAM+SYSTEM together let you extract password hashes (samdump2). UserAssist values are ROT13-encoded program names.
- frequency: med
- depth: deep
- sources: https://trailofbits.github.io/ctf/forensics/, https://or10nlabs.tech/defcon-dfir-ctf-2018/

## Encrypted ZIP: crack or known-plaintext (bkcrack)
- category: forensics
- signal: Password-protected .zip. Check method: `7z l -slt a.zip` shows ZipCrypto (legacy) vs AES. You may have/know one plaintext file inside.
- technique: AES/unknown pw: zip2john -> john/hashcat + rockyou. ZipCrypto + you know >=12 bytes (8 contiguous) of any one entry (fixed header): bkcrack known-plaintext attack.
- tool/command: zip2john a.zip > h; john --wordlist=rockyou.txt h    # ZipCrypto: bkcrack -C a.zip -c secret.png -p known_header.bin
- gotchas: bkcrack only beats ZipCrypto, NOT AES. Known plaintext can be a standard PNG/PDF header of a same-archive file. Recover keys then bkcrack -d to decrypt.
- frequency: med
- depth: deep
- sources: https://github.com/Skriep/CTF-Crypto-bkcrack, https://mariuszbartosik.com/buckeye-ctf-2024-reduce_recycle-write-up/

## QR / barcode in image
- category: forensics
- signal: Image contains a full/partial QR/barcode, or stego extraction yields a QR-looking PNG. May be inverted, low-contrast, or split across bit planes.
- technique: Decode programmatically; repair contrast/inversion/threshold first if the scan fails.
- tool/command: zbarimg image.png   # if it fails: convert image.png -negate -threshold 50% fixed.png; zbarimg fixed.png
- gotchas: Partial QR may need missing finder patterns drawn back. Try qrazybox (web) to rebuild damaged QRs.
- frequency: low
- depth: quick
- sources: https://www.neerajlovecyber.com/steganography-cheatsheet-for-ctf-beginners, https://trailofbits.github.io/ctf/forensics/