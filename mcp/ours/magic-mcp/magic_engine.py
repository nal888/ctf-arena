#!/usr/bin/env python3
"""
magic_engine — CyberChef-"Magic"-style automatic decoder for CTF blobs.

Best-first recursive search: at each node, every operation whose input *looks*
applicable is speculatively run; children are scored (Shannon entropy ↓,
chi-squared-vs-English ↓, printable ratio ↑, magic-byte file hits, and a
flag-crib regex), the frontier is expanded best-first, and the search
short-circuits the moment a flag-shaped string appears.

Pure stdlib. Usable standalone (`python3 magic_engine.py <blob>`) or via the MCP.
"""
from __future__ import annotations
import base64, binascii, codecs, urllib.parse, zlib, gzip, bz2, lzma, quopri
import re, math, heapq, html, string, io

# ---------- scoring helpers ----------
_ENG = {  # English letter frequency %
    'a':8.17,'b':1.49,'c':2.78,'d':4.25,'e':12.70,'f':2.23,'g':2.02,'h':6.09,
    'i':6.97,'j':0.15,'k':0.77,'l':4.03,'m':2.41,'n':6.75,'o':7.51,'p':1.93,
    'q':0.10,'r':5.99,'s':6.33,'t':9.06,'u':2.76,'v':0.98,'w':2.36,'x':0.15,
    'y':1.97,'z':0.07}
FLAG_CRIB = re.compile(rb'(flag|ctf|key|pico|htb|grey|fwd|cyber|sun|uiuctf|dice|corctf|bcactf|n0ps|wgmy)\{[ -~]{0,200}\}', re.I)
# generic word{word} — a HINT only (could be rot13 of a real flag), never a definitive stop
GENERIC_CRIB = re.compile(rb'[A-Za-z][A-Za-z0-9_]{2,24}\{[\x20-\x7e]{1,200}\}')
_BODY_OK = set(string.ascii_letters + string.digits + "_- ")

def known_flag(data: bytes):
    """Definitive flag = a KNOWN prefix + braces. This is the only thing that stops the search."""
    m = FLAG_CRIB.search(data)
    return m.group(0) if m else None

def generic_braces(data: bytes):
    """Flag-shaped with clean body but unknown prefix — a strong hint, scored not stopped."""
    m = GENERIC_CRIB.search(data)
    if m:
        body = m.group(0)[m.group(0).find(b'{')+1:-1]
        if body and sum(1 for c in body if chr(c) in _BODY_OK)/len(body) >= 0.85:
            return m.group(0)
    return None
MAGIC = {  # file signatures -> "we decoded into a real file"
    b'\x89PNG': 'PNG', b'\xff\xd8\xff': 'JPEG', b'GIF8': 'GIF', b'PK\x03\x04': 'ZIP',
    b'%PDF': 'PDF', b'\x7fELF': 'ELF', b'\x1f\x8b': 'gzip', b'BZh': 'bzip2',
    b'Rar!': 'RAR', b'\xfd7zXZ': 'xz', b'ustar': 'tar', b'OggS': 'OGG',
    b'RIFF': 'RIFF/WAV', b'\x42\x4d': 'BMP', b'ID3': 'MP3', b'7z\xbc\xaf': '7z',
}

def shannon(data: bytes) -> float:
    if not data: return 8.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data); ent = 0.0
    for f in freq:
        if f:
            p = f/n; ent -= p*math.log2(p)
    return ent

def printable_ratio(data: bytes) -> float:
    if not data: return 0.0
    ok = set(bytes(string.printable, 'ascii'))
    return sum(1 for b in data if b in ok)/len(data)

_COMMON_BIGRAMS = {"th","he","in","er","an","re","on","at","en","nd","ti","es","or",
    "te","of","ed","is","it","al","ar","st","to","nt","ng","se","ha","as","ou","io",
    "le","ve","co","me","de","hi","ri","ro","ic","ne","ea","ra","ce","li","ll","lo",
    "be","ma","si","om","ur","ca","el","ta","la","ns","di","fo","ho","pe","ec","pr","wo","or"}
def wordiness(data: bytes) -> float:
    """Fraction of bigrams that are common English — separates real words from gibberish."""
    try: s = data.decode("ascii").lower()
    except Exception: return 0.0
    bg = [s[i:i+2] for i in range(len(s)-1) if s[i].isalpha() and s[i+1].isalpha()]
    if len(bg) < 2: return 0.0
    return sum(1 for b in bg if b in _COMMON_BIGRAMS) / len(bg)

def chi2_english(data: bytes) -> float:
    letters = [b for b in data.lower() if 97 <= b <= 122]
    if len(letters) < 4: return 999.0
    n = len(letters); chi = 0.0
    obs = [0]*26
    for b in letters: obs[b-97] += 1
    for i,ch in enumerate(string.ascii_lowercase):
        exp = _ENG[ch]/100*n
        if exp > 0: chi += (obs[i]-exp)**2/exp
    return chi/n  # normalised

def magic_hit(data: bytes):
    for sig,name in MAGIC.items():
        if data.startswith(sig): return name
    return None

def score(data: bytes):
    """Higher = more 'solved-looking'. Returns (score, flag_bool, note)."""
    if not data: return (-50, False, "empty")
    kf = known_flag(data)
    if kf:
        return (1000, True, kf.decode('latin1', 'replace')[:120])   # ONLY known prefix stops search
    mb = magic_hit(data)
    if mb:
        return (400, False, f"file:{mb}")
    pr = printable_ratio(data)
    ent = shannon(data)
    alpha = sum(1 for b in data if 65 <= b <= 90 or 97 <= b <= 122 or b == 32) / len(data)
    s = 0.0
    s += pr*30                      # printable is good
    s += alpha*30                   # ...but letters/words >> symbol soup (kills rot47 garbage)
    s -= ent*8                      # low entropy is good (decoded < encoded)
    if pr > 0.95 and alpha > 0.5:
        s += 30 - min(chi2_english(data), 30)   # english-ish bonus
        s += wordiness(data) * 40               # real words >> rot-shifted gibberish
    if pr < 0.6:
        s -= 40                     # likely still binary/garbage
    if len(data) < 5:
        s -= 30                     # tiny outputs are usually over-decoded fragments (entropy is unreliable there)
    gb = generic_braces(data)
    if gb:
        s += 250                    # flag-shaped (unknown prefix) — strong hint, not a stop
        return (s, False, f"braces? {gb.decode('latin1','replace')[:60]}")
    return (s, False, f"ent{ent:.1f} pr{pr:.2f}")

def looks_clean(data: bytes) -> bool:
    """Plain readable text with no flag-braces — applying rot/xor/atbash would only OVER-decode it.
    (Brace-bearing text is excluded so a rot/atbash'd flag still gets transformed back.)"""
    if len(data) < 4 or b'{' in data or b'}' in data: return False
    pr = printable_ratio(data)
    alpha = sum(1 for b in data if 65 <= b <= 90 or 97 <= b <= 122 or b == 32) / len(data)
    return pr > 0.92 and alpha > 0.7

# ---------- operations: each returns list of (label, bytes) ----------
_B64 = re.compile(rb'^[A-Za-z0-9+/=\s]+$'); _B64U = re.compile(rb'^[A-Za-z0-9\-_=\s]+$')
_B32 = re.compile(rb'^[A-Z2-7=\s]+$'); _HEX = re.compile(rb'^[0-9a-fA-F\s]+$')
_B58 = re.compile(rb'^[1-9A-HJ-NP-Za-km-z]+$'); _BIN = re.compile(rb'^[01\s]+$')
_DEC = re.compile(rb'^[0-9\s,]+$'); _MORSE = re.compile(rb'^[.\-/ \t\n]+$')
_B58ALPH = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _try(fn):
    try: return fn()
    except Exception: return None

def op_b64(d):
    if len(d) < 4 or not _B64.match(d): return []
    r = _try(lambda: base64.b64decode(re.sub(rb'\s',b'',d)+b'===', validate=False))
    return [("base64", r)] if r else []

def op_b64url(d):
    if len(d) < 4 or not _B64U.match(d) or b'-' not in d and b'_' not in d: return []
    r = _try(lambda: base64.urlsafe_b64decode(re.sub(rb'\s',b'',d)+b'==='))
    return [("base64url", r)] if r else []

def op_b32(d):
    if len(d) < 4 or not _B32.match(d): return []
    s = re.sub(rb'\s',b'',d); s += b'='*(-len(s)%8)
    r = _try(lambda: base64.b32decode(s))
    return [("base32", r)] if r else []

_HEXSEP = re.compile(rb'0x|\\x|[\s:,;_\-]')
def op_b16(d):
    s = _HEXSEP.sub(b'', d)                         # strip 0x / \x / : - , ; _ space separators
    if len(s) < 4 or len(s) % 2 or not re.match(rb'^[0-9a-fA-F]+$', s): return []
    r = _try(lambda: binascii.unhexlify(s))
    return [("hex", r)] if r else []

def op_b85(d):
    r = _try(lambda: base64.b85decode(re.sub(rb'\s',b'',d)))
    return [("base85", r)] if r and printable_ratio(r) > 0.3 else []

def op_a85(d):
    r = _try(lambda: base64.a85decode(re.sub(rb'\s',b'',d)))
    return [("ascii85", r)] if r and printable_ratio(r) > 0.3 else []

def op_b58(d):
    s = re.sub(rb'\s',b'',d)
    if len(s) < 4 or not _B58.match(s): return []
    def dec():
        num = 0
        for c in s: num = num*58 + _B58ALPH.index(c)
        out = num.to_bytes((num.bit_length()+7)//8, 'big')
        pad = len(s)-len(s.lstrip(b'1'))
        return b'\x00'*pad + out
    r = _try(dec)
    return [("base58", r)] if r else []

def op_url(d):
    if b'%' not in d: return []
    r = _try(lambda: urllib.parse.unquote_to_bytes(d))
    return [("url", r)] if r and r != d else []

def op_html(d):
    if b'&' not in d: return []
    r = _try(lambda: html.unescape(d.decode('latin1')).encode('latin1'))
    return [("html-entity", r)] if r and r != d else []

def op_rot13(d):
    if not any(65<=b<=90 or 97<=b<=122 for b in d): return []
    r = _try(lambda: codecs.decode(d.decode('latin1'),'rot13').encode('latin1'))
    return [("rot13", r)] if r else []

def op_rotN(d):
    # brute all 25 shifts, but only emit the few that look most english/crib
    if not any(97<=b<=122 or 65<=b<=90 for b in d): return []
    out = []
    for k in range(1,26):
        def sh(b,k=k):
            if 97<=b<=122: return (b-97+k)%26+97
            if 65<=b<=90: return (b-65+k)%26+65
            return b
        r = bytes(sh(b) for b in d)
        out.append((f"rot{k}", r))
    out.sort(key=lambda x: score(x[1])[0], reverse=True)
    return out[:3]

def op_rot47(d):
    if not any(33<=b<=126 for b in d): return []
    r = bytes((b-33+47)%94+33 if 33<=b<=126 else b for b in d)
    return [("rot47", r)]

def op_atbash(d):
    r = bytes(90-(b-65) if 65<=b<=90 else (122-(b-97) if 97<=b<=122 else b) for b in d)
    return [("atbash", r)] if r != d and any(65<=b<=122 for b in d) else []

def op_reverse(d):
    return [("reverse", d[::-1])] if len(d) > 3 else []

def op_binary(d):
    s = re.sub(rb'\s',b'',d)
    if len(s) < 8 or len(s)%8 or not _BIN.match(d): return []
    r = _try(lambda: bytes(int(s[i:i+8],2) for i in range(0,len(s),8)))
    return [("binary", r)] if r else []

def op_decimal(d):
    if not _DEC.match(d): return []
    parts = re.split(rb'[\s,]+', d.strip())
    r = _try(lambda: bytes(int(p) for p in parts if p and 0<=int(p)<=255))
    return [("decimal", r)] if r and len(r) > 1 else []

def op_morse(d):
    if not _MORSE.match(d) or b'.' not in d and b'-' not in d: return []
    M = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
         '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
         '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
         '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0',
         '.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6',
         '--...':'7','---..':'8','----.':'9'}
    def dec():
        words = d.decode().strip().replace('/',' / ').split()
        return ''.join(M.get(w,' ' if w=='/' else '?') for w in words).encode()
    r = _try(dec)
    return [("morse", r)] if r else []

def op_decompress(d):
    out = []
    for name,fn in [("gzip",lambda: gzip.decompress(d)),
                    ("zlib",lambda: zlib.decompress(d)),
                    ("zlib-raw",lambda: zlib.decompress(d,-15)),
                    ("bzip2",lambda: bz2.decompress(d)),
                    ("lzma",lambda: lzma.decompress(d))]:
        r = _try(fn)
        if r: out.append((name, r))
    return out

def op_quopri(d):
    if b'=' not in d: return []
    r = _try(lambda: quopri.decodestring(d))
    return [("quoted-printable", r)] if r and r != d and printable_ratio(r) > 0.5 else []

def op_escapes(d):
    if rb'\x' not in d and rb'\u' not in d: return []
    r = _try(lambda: codecs.decode(d.decode('latin1'), 'unicode_escape').encode('latin1'))
    return [("unescape", r)] if r and r != d else []

def op_a1z26(d):
    toks = [t for t in re.split(rb'[\s,.\-_]+', d.strip()) if t]
    nums = _try(lambda: [int(t) for t in toks])
    if not nums or len(nums) < 3 or not all(1 <= n <= 26 for n in nums): return []
    return [("a1z26", bytes(n + 96 for n in nums))]

def op_xor1(d):
    # single-byte XOR brute — only when data is short-ish & not already printable text
    if len(d) > 4096 or printable_ratio(d) > 0.95: return []
    out = []
    for k in range(1,256):
        r = bytes(b^k for b in d)
        sc = score(r)
        if sc[1] or sc[0] > 25:   # only keep promising
            out.append((f"xor{k:#04x}", r))
    out.sort(key=lambda x: score(x[1])[0], reverse=True)
    return out[:3]

OPS = [op_b64, op_b64url, op_b32, op_b16, op_b85, op_a85, op_b58, op_url, op_html,
       op_quopri, op_escapes, op_rot13, op_rotN, op_rot47, op_atbash, op_reverse,
       op_binary, op_decimal, op_a1z26, op_morse, op_decompress, op_xor1]
BRUTE = {op_rotN, op_rot47, op_xor1, op_atbash}   # noisy — only fire at shallow depth
NOISY = BRUTE | {op_rot13, op_reverse}             # transforms that over-decode already-clean text

# ---------- best-first recursive search ----------
def magic(data, depth=8, max_nodes=4000, max_results=6):
    if isinstance(data, str): data = data.encode('latin1', 'replace')
    data = data.strip()
    seen = set(); results = []; nodes = 0
    base_sc, base_flag, base_note = score(data)
    # frontier: (-score, tie, data, chain, level)
    tie = 0
    frontier = [(-base_sc, tie, data, [], 0)]
    while frontier and nodes < max_nodes:
        negs, _, cur, chain, lvl = heapq.heappop(frontier)
        sc, flag, note = score(cur)
        if chain or flag:  # record any decode, AND a root input that's already a flag
            rscore = sc - 3.0*len(chain)        # Occam: prefer the shallowest clean decode
            results.append({"chain": chain or ["(already decoded)"], "score": round(sc,1),
                            "rscore": rscore, "flag": flag, "note": note, "output": _preview(cur)})
        if flag:   # short-circuit: a KNOWN-prefix flag is the answer
            break
        if lvl >= depth: continue
        cur_clean = looks_clean(cur)                   # CyberChef principle: only recurse if it improves
        for op in OPS:
            if op in NOISY and (lvl >= 4 or cur_clean): continue   # don't transform already-clean text
            for label, child in op(cur):
                if not child: continue
                nodes += 1
                h = hash(child[:200]) ^ (len(child)<<1)
                if h in seen: continue
                seen.add(h)
                csc = score(child)[0]
                if csc < sc - 60: continue            # prune sharply-worse branches
                tie += 1
                heapq.heappush(frontier, (-csc, tie, child, chain+[label], lvl+1))
    # best flag first, then best depth-penalized score; dedupe by output
    results.sort(key=lambda r: (r["flag"], r.get("rscore", r["score"])), reverse=True)
    uniq, out = set(), []
    for r in results:
        k = r["output"][:80]
        if k in uniq: continue
        uniq.add(k); out.append(r)
        if len(out) >= max_results: break
    return {"input_preview": _preview(data), "nodes": nodes,
            "best": out[0] if out else None, "candidates": out}

def _preview(b, n=240):
    try:
        s = b.decode('utf-8')
    except Exception:
        s = b.decode('latin1', 'replace')
    s = s if len(s) <= n else s[:n] + f"… (+{len(s)-n} more)"
    return s

if __name__ == "__main__":
    import sys, json
    blob = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(magic(blob), indent=2, ensure_ascii=False))
