---
title: osint
type: note
permalink: ctf-vault/osint
---

# OSINT — CTF Pattern Vault

> Mined from real writeups, deduped, sorted by frequency (high→low, quick wins first). 23 patterns. Recognition-first: observe **signal** → run **tool/command**.

---

## EXIF GPS + hidden text-field extraction
- category: osint
- signal: Given a photo (.jpg/.png/.tiff) and asked WHERE it was taken or for a hidden flag; image is a real file, not a stripped social download
- technique: Dump all metadata first. GPS lat/lon goes straight to Maps. Treat UserComment/Artist/Description/Comment as payloads: flag is often verbatim there, or base64/URL needing decode.
- tool/command: exiftool image.jpg ; exiftool -UserComment -Artist -ImageDescription image.jpg | sed 's/.*: //' | base64 -d 2>/dev/null
- gotchas: FB/IG/Twitter strip EXIF — no GPS means scrubbed, pivot to visual geo. GPS may be a planted red herring (cross-check Description text). Decoded comments can be troll links; don't stop at first decode.
- frequency: high
- depth: quick
- sources: https://medium.com/@F1nD3r/space-heroes-ctf-osint-section-writeup-dce873b1a379, https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b, https://ctftime.org/writeup/29856

## Reverse image search (Yandex-first rotation)
- category: osint
- signal: Image with no useful EXIF but a distinctive landmark, building, signage, architecture, or product
- technique: Crop to the unique feature first, then run through multiple engines. Yandex is strongest for non-Western/Eastern-Europe/Asia; Google Lens + Bing for Western.
- tool/command: Crop to landmark, then upload to: yandex.com/images , lens.google.com , tineye.com , Bing visual search
- gotchas: Reverse-searching a generic scene (lake, field) returns noise — crop to signage/statue/organ. Google often fails where Yandex succeeds for non-Western imagery.
- frequency: high
- depth: quick
- sources: https://medium.com/@F1nD3r/space-heroes-ctf-osint-section-writeup-dce873b1a379, https://tomsitcafe.com/2024/11/13/the-art-of-osint-locating-where-a-photo-was-taken/, https://www.siberoloji.com/reverse-image-search-for-location-discovery-osint-geolocation-tracking-from-images/

## Username enumeration / cross-platform pivot
- category: osint
- signal: You have a single username/handle/display name and need the person's other accounts, bio, real name, email, or location
- technique: People reuse handles. Spray across 400-600 sites to find Reddit/Spotify/GitHub/forum profiles, then pivot through bios for real name, email, location.
- tool/command: sherlock USERNAME ; web: https://whatsmyname.app/
- gotchas: Sherlock false-positives on sites that 200 for any name — verify each hit by visiting. Common usernames produce noise; weight unusual handles.
- frequency: high
- depth: quick
- sources: https://book.jorianwoltjer.com/web/enumeration/osint, https://cybersec.reviews/write-ups/tracelabsosintforgood/, https://warnerchad.medium.com/sakura-room-osint-ctf-writeup-8e688394a44e

## Wayback Machine for dead/changed pages
- category: osint
- signal: Challenge references a URL/file that 404s now, a deleted tweet/post/pastebin, or hints at page history
- technique: Pull archived snapshots — the flag lived in a past capture. Compare captures across dates to find the version with the clue.
- tool/command: http://web.archive.org/web/*/example.com ; CLI: waybackurls example.com | sort -u  (or gau example.com)
- gotchas: Not every page is archived; try multiple dates + calendar view. For deleted posts, archive the profile URL not just the post. Deleted pastebin content often survives in Wayback.
- frequency: high
- depth: quick
- sources: https://ctftime.org/writeup/21532, https://medium.com/thedeephub/2024-n00bz-ctf-pastebin-writeup-aaa8991187ed, https://ctftime.org/writeup/18176

## Google dorking for documents/leaked files
- category: osint
- signal: Challenge points at an org/agency and asks for a specific doc, PDF, config, or exposed file
- technique: Combine site: + filetype: + a unique keyword from the prompt to surface indexed PDFs, configs, or directory listings holding the flag or pivot.
- tool/command: site:agency.gov "keyword" filetype:pdf ; intitle:"index of" ; inurl:admin
- gotchas: PDF/Office metadata often holds the flag even when the body doesn't — download and run exiftool/strings on the hit.
- frequency: med
- depth: quick
- sources: https://medium.com/@theos.offsec/rootcon-15-ctf-writeup-osint-d580ecb9944d, https://github.com/tracelabs/ctf-prep/blob/main/how-to.md

## Email -> Google account enrichment (GHunt/Epieos/holehe)
- category: osint
- signal: You recover a target's email (whois, profile, business card), especially @gmail.com, and need linked accounts/activity
- technique: Resolve a Gmail to its Google account: profile name/photo, Maps reviews/contributions (leak location history), public Calendar, YouTube. holehe/Epieos map an email to which services it's registered on.
- tool/command: python ghunt.py email target@gmail.com ; holehe target@example.com ; web: epieos.com
- gotchas: GHunt needs valid Google session cookies configured first. Google Maps 'Contributions' and an exposed public Calendar are classic flag spots — check both.
- frequency: med
- depth: quick
- sources: https://medium.com/@theos.offsec/rootcon-15-ctf-writeup-osint-d580ecb9944d, https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b

## crt.sh certificate transparency subdomain discovery
- category: osint
- signal: You have a root domain and need hidden/internal subdomains (staging, dev, vpn, admin) not in DNS/search
- technique: Every TLS cert is logged publicly. Query CT logs with wildcard to enumerate every subdomain ever issued a cert, including dead/internal hosts.
- tool/command: curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
- gotchas: crt.sh times out on big domains — retry or use JSON. Returns expired+wildcard entries; dedupe and resolve to find live hosts. Cross-check Censys.
- frequency: med
- depth: quick
- sources: https://book.jorianwoltjer.com/web/enumeration/osint, https://www.sherlockforensics.com/blog/osint-recon-beginners-guide.html

## Passive subdomain enum (subfinder/amass)
- category: osint
- signal: Root domain target; need a fast comprehensive subdomain list from many passive sources at once
- technique: One pass aggregating CT logs + search scraping + DNS sources to surface attack-surface hosts, then resolve live ones.
- tool/command: subfinder -d example.com -silent | httpx -silent ; amass enum -passive -d example.com
- gotchas: Passive only finds what's published; combine with crt.sh. Resolve results (httpx/dnsx) to drop dead hosts before pivoting.
- frequency: med
- depth: quick
- sources: https://www.sherlockforensics.com/blog/osint-recon-beginners-guide.html, https://book.jorianwoltjer.com/web/enumeration/osint

## DNS record harvesting (TXT/MX/NS)
- category: osint
- signal: You have a domain and need infra clues: mail provider, verification tokens, SPF, nameservers, or a flag in TXT
- technique: Pull all record types. TXT leaks SPF includes and service verification tokens; MX reveals mail provider; flags sometimes hide directly in TXT.
- tool/command: dig txt example.com +short ; dig mx example.com +short ; dig ns example.com +short
- gotchas: ANY is often refused by resolvers — query record types individually. Check both apex and www/subdomains.
- frequency: med
- depth: quick
- sources: https://book.jorianwoltjer.com/web/enumeration/osint, https://www.sherlockforensics.com/blog/osint-recon-beginners-guide.html

## Office/PDF document metadata + embedded media
- category: osint
- signal: Given .odt/.docx/.pptx/.pdf and the flag isn't in the visible text
- technique: Office docs are ZIP archives — unzip and inspect embedded thumbnails, media, and metadata (author/dates) where flags/images hide.
- tool/command: unzip doc.docx -d out/ ; ls out/word/media/ out/Thumbnails/ ; exiftool out/ -r ; for pdf use exiftool/pdfinfo
- gotchas: Thumbnails/ holds a rendered preview that can show content removed from the live doc. Check core.xml/meta.xml for author/dates. PDF metadata often carries the flag.
- frequency: med
- depth: quick
- sources: https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b, https://github.com/tracelabs/ctf-prep/blob/main/how-to.md

## Shodan/Censys passive IP & service pivot
- category: osint
- signal: You recovered an IP (often decoded from doc/image metadata) or a domain and need open ports/banners/services
- technique: Passively query the IP/domain for open ports, banners, cert SANs, and exposed panels. Banners and cert names reveal the next host or the flag.
- tool/command: shodan host <ip> ; web: https://www.shodan.io/host/<ip> , https://search.censys.io/hosts/<ip>
- gotchas: Don't actively scan — challenge may key off historical index data. Banners are timestamped (note scan date). Pair with the metadata-IP step that feeds it.
- frequency: med
- depth: quick
- sources: https://noob-atbash.github.io/CTF-writeups/csictf-20/osint/osint.html, https://zenn.dev/platina/articles/5619b3fa03c8ca?locale=en

## Signage / license plate / QR as geolocators
- category: osint
- signal: Image contains a license plate, street sign, QR code, or business name/phone
- technique: Extract the text artifact: plate format/color reveals country (diplomatic codes); QR decodes to address/URL; business name+phone resolves via Google Maps/Foursquare listing.
- tool/command: zbarimg image.png ; plate format -> worldlicenseplates.com ; search '"business name" city' on Google Maps -> confirm via Foursquare venue
- gotchas: Plate region codes and sign fonts/language are strong country tells. A readable phone number is often the fastest pivot to an exact address.
- frequency: med
- depth: quick
- sources: https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b, https://www.siberoloji.com/reverse-image-search-for-location-discovery-osint-geolocation-tracking-from-images/

## Specialized public trackers (flight/ship/aircraft/space/wildlife)
- category: osint
- signal: Image/clue shows an aircraft tail number (e.g. JA222A), ship name, satellite/space object, or tagged animal
- technique: Resolve the identifier in a domain-specific registry/tracker to get owner, route, position, or history. Match serial/reg to records.
- tool/command: Aircraft: airfleets.net , flightradar24 ; ships: marinetraffic.com ; space: theskylive.com ; wildlife: ocearch.org/tracker
- gotchas: Some trackers gate history behind membership (FR24). Most have a date/time toggle — use it to retrieve position on the challenge's specified date.
- frequency: med
- depth: quick
- sources: https://medium.com/@F1nD3r/space-heroes-ctf-osint-section-writeup-dce873b1a379, https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b

## WiGLE / cell-tower RF geolocation
- category: osint
- signal: Given a WiFi BSSID (MAC) or unusual SSID, or a cell tower ID (MCC/MNC/LAC/CID), and asked for a physical location
- technique: Look up the BSSID/SSID in WiGLE's wardriving DB for a lat/lon; map cell IDs via opencellid. MAC OUI (first 3 octets) = hardware vendor.
- tool/command: https://wigle.net/ search by SSID or netid=BSSID ; cell: opencellid.org / cellmapper.net ; MAC vendor: macvendors.com
- gotchas: WiGLE needs a free account. Generic SSIDs (linksys/carrier defaults) only narrow to region — search by BSSID. Get all four of MCC/MNC/LAC/CID for cell lookup.
- frequency: med
- depth: quick
- sources: https://warnerchad.medium.com/sakura-room-osint-ctf-writeup-8e688394a44e, https://infosecwriteups.com/approaching-ctf-osint-challenges-learn-by-example-b92be1dddc8d

## Breach / credential lookup
- category: osint
- signal: You have an email or username and the challenge hints at a leaked password, breach, or paste dump
- technique: Check breach aggregators for the account; search paste sites by keyword/MD5 for dumped creds (sometimes WiFi creds via onion paste).
- tool/command: https://haveibeenpwned.com/ ; https://dehashed.com/ ; pastebin/DeepPaste keyword or MD5 search
- gotchas: HIBP confirms breach but not plaintext; dehashed/leaks needed for actual creds. Paste sites are volatile/onion — may need Tor. Treat recovered creds as the pivot, not the flag.
- frequency: low
- depth: quick
- sources: https://ctf.support/osint/, https://warnerchad.medium.com/sakura-room-osint-ctf-writeup-8e688394a44e

## Description/text lead beats coordinates
- category: osint
- signal: EXIF GPS points somewhere implausible, but a Description/caption names a town or region
- technique: When GPS is a red herring, pivot to the named place text. Google the region, then visually match the photo to candidate spots (e.g. a specific named lake).
- tool/command: Google '<region name> lake/landmark' ; compare candidate images visually ; confirm in Google Earth
- gotchas: Authors plant fake GPS to mislead. Always reconcile GPS with text fields; the text is usually the true lead.
- frequency: med
- depth: quick
- sources: https://ctftime.org/writeup/29856, https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b

## Landmark geolocation + Street View confirmation
- category: osint
- signal: Photo with no GPS and no reverse-image hit, but has signage/language, architecture, vegetation, or distinctive storefronts
- technique: Read signage language to narrow country; ID architecture/vegetation/climate; confirm exact spot by matching buildings/crosswalks/storefronts in Google Street View / Earth.
- tool/command: Google Earth + Street View to match buildings ; crowd help: r/WhereIsThis, Geoguessr, geotips ; right-click osm.org for feature tags
- gotchas: Signage language != country (immigrant neighborhoods). Iterative manual work — combine 3+ signals. Street View capture may pre/post-date the photo; use the time slider.
- frequency: high
- depth: deep
- sources: https://tomsitcafe.com/2024/11/13/the-art-of-osint-locating-where-a-photo-was-taken/, https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b, https://infosecwriteups.com/image-geospatial-osint-7cf8560b54f6

## Social media timeline & geo/encoding pivot
- category: osint
- signal: You've reached a target's Twitter/Reddit/Spotify/LinkedIn and need a location, a date, or a hidden flag fragment
- technique: Mine posts for embedded photos/maps, geotags, timestamps. Decode encoded bio/playlist descriptions (base58/base64). Read acrostics/first-letters across post or track titles for assembled flag pieces.
- tool/command: X advanced search: keyword since:2021-01-01 until:2021-01-31 from:user ; CyberChef Magic / From Base58 / From Base64 on bios & playlist descriptions
- gotchas: Base58 (no 0/O/I/l) distinguishes from base64 (has +/=). Track/handle renames break links — use archived versions. Playlist/track ordering can be the message (acrostic).
- frequency: high
- depth: deep
- sources: https://medium.com/@hadir3mr/0xfun-ctf-2026-osint-writeup-e35ff2afdf3d, https://warnerchad.medium.com/sakura-room-osint-ctf-writeup-8e688394a44e, https://warnerchad.medium.com/sector035-osint-ctf-2019-writeup-a8b766c9cbf

## Shadow / sun-angle chronolocation
- category: osint
- signal: Photo with no GPS but visible shadows, sun position, and a roughly-known location; asked for time/date or to confirm hemisphere
- technique: Use shadow direction + length with SunCalc to fix hemisphere, season, and approximate time-of-day; combine with other geo signals to confirm.
- tool/command: https://www.suncalc.org/ — enter candidate location, match the sun azimuth/elevation to the photo's shadows
- gotchas: Shadows give hemisphere/time, not an exact spot — one signal among several. Need a candidate location first to validate against.
- frequency: med
- depth: deep
- sources: https://tomsitcafe.com/2024/11/13/the-art-of-osint-locating-where-a-photo-was-taken/, https://zenn.dev/platina/articles/5619b3fa03c8ca?locale=en

## Landmark + OpenStreetMap/Overpass feature query
- category: osint
- signal: Photo with identifiable but unnamed features (church spire, water tower, road junction, transit stop, shop type) in a roughly-known region
- technique: Extract 3 unique features, query OSM for objects matching those tags within a bounding box to enumerate candidates; verify with Street View.
- tool/command: https://overpass-turbo.eu/ (right-click feature on osm.org for tags) ; or Python overpy filtering bbox + amenity/man_made tags
- gotchas: Overpass syntax is finicky — start from a wizard query. Combine 2-3 features (intersection of sets) to cut candidates. Street View may be newer/older than the photo.
- frequency: med
- depth: deep
- sources: https://zenn.dev/platina/articles/5619b3fa03c8ca?locale=en, https://infosecwriteups.com/image-geospatial-osint-7cf8560b54f6

## whois + git history + paste-site identity chain
- category: osint
- signal: Domain or org name given; need a person, email, or credential behind it
- technique: Chain whois registrant -> repo commit authors -> leaked secrets/paste dumps. Classic NahamCon-style pivot ladder.
- tool/command: whois example.com ; git clone repo && git log --format='%ae' | sort -u ; search grep.app/pastebin for tokens ; keepass2john db.kdbx > h && john h
- gotchas: Registrant often redacted by privacy proxy — pivot to historical whois (whoxy/viewdns) or Wayback of the site. Commit emails reveal real identities the website hides.
- frequency: med
- depth: deep
- sources: https://infosecwriteups.com/approaching-ctf-osint-challenges-learn-by-example-b92be1dddc8d, https://book.jorianwoltjer.com/web/enumeration/osint

## Historical Street View / satellite time machine
- category: osint
- signal: Need a feature that no longer exists — old advertisement, demolished building, past signage, or a winner's name on old signage
- technique: Roll the Street View/satellite timeline back years to read signage/ads visible only in an older capture; pick the snapshot near the known event date.
- tool/command: Google Maps Street View -> click the clock/time icon -> set earlier date ; Google Earth Pro historical imagery slider
- gotchas: Coverage varies by location/year; rural areas may lack old captures. Combine with the known event date to pick the right snapshot.
- frequency: low
- depth: deep
- sources: https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b, https://zenn.dev/platina/articles/5619b3fa03c8ca?locale=en

## Blockchain explorer wallet/tx tracing
- category: osint
- signal: Challenge supplies a crypto wallet address or transaction hash
- technique: Trace funds/identity via a public explorer — follow inputs/outputs, find labeled exchange deposit addresses, OP_RETURN data, or tx notes carrying the pivot/flag.
- tool/command: etherscan.io (ETH) or blockchain.com/explorer (BTC): paste tx hash/address, follow the transaction graph and check embedded/OP_RETURN data
- gotchas: Hint may be address reuse linking to a labeled exchange/identity, or data encoded in a transaction. Note the exact tx hash and follow upstream.
- frequency: low
- depth: deep
- sources: https://medium.com/@L00ck3r/diverctf-osint-writeup-2024-7589d131809b, https://ctf.support/osint/
## Image-encoded Brainfuck + username→social persona OSINT (boroCTF "Satoshi Hunt")
- **signal:** OSINT trail (username-checker hit) → social account whose post has an image that's just `+ - < > [ ] . ,` → it's **Brainfuck source rendered as a (often near-black, low-contrast) image**.
- **technique:**
  1. trail: provided username-search output → handle on a real platform (HackenProof) → same handle on X (@SatoshiNakamuda). bio acrostic / "FirstWords" = take first word of each line → author signature (ForeverFlames).
  2. X tweets behind login: read via guest API (POST api.twitter.com/1.1/guest/activate.json for guest_token → UserByScreenName GraphQL for bio/location/tweet count). If tweets stay empty, have the human (logged in) read them.
  3. decode the image: brighten (`convert img -level 0%,4% -negate`), then custom **monospace OCR** — rows by horizontal projection, glyphs by column gaps (~15px pitch), classify each by SHAPE (tiny-bottom=`.`, thin=`-`, center-vstroke=`+`, edge-vstroke=`[`/`]`, chevron=`<`/`>`). Run through a BF interpreter.
  4. GOTCHA: get the **pitch exact** (measure glyph start-to-start spacing, not width+gap) — a 1px error mis-divides long runs and drops a `-` per run → output reads then drifts upward. Sanity check: the leading `+++[...]` multiply-loop should print the first few chars cleanly.
- **flag-format gotcha:** boroCTF gives NO format on some challenges and mixes `boro{}` / `CTF{REDACTED}` / `flag{REDACTED}`. If `boro{X}` is "incorrect", retry `CTF{REDACTED}` SAME value before doubting the answer. Satoshi Hunt = `CTF{REDACTED}` ("highest point in Japan" tweet).
- **tools:** playwright/headless-chrome (`--dump-dom`) for SPA profiles; X guest GraphQL; PIL/numpy custom OCR.
