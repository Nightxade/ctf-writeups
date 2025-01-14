import os

PATH = "_writeups"
CATEGORIES = set([b"crypto", b"rev", b"pwn", b"misc", b"forensics", b"web", b"osint", b"algo"])

for year in os.listdir(PATH):
    year_path = os.path.join(PATH, year)

    if year == '_site' or not os.path.isdir(year_path):
        continue

    for ctf in os.listdir(year_path):
        ctf_path = os.path.join(year_path, ctf)

        for category in os.listdir(ctf_path):
            category_path = os.path.join(ctf_path, category)

            if category == 'index.md': continue

            for writeup in os.listdir(category_path):
                writeup_path = os.path.join(category_path, writeup)

                txt = open(writeup_path, 'rb').read().split(b'\r\n')
                tag_i = list(filter(lambda a: b'tags: ' == a[1][:6], enumerate(txt)))[0][0]
                tags = txt[tag_i][6:].split(b' ')
                ptag, stag = tags[0], tags[1:]
                if ptag not in CATEGORIES:
                    ptag = b"FIX"
                tags = [ptag] + [ptag + b'/' + tag if tag not in CATEGORIES else tag for tag in stag]

                txt[tag_i] = b'tags: ' + b' '.join(tags)
                txt_w = open(writeup_path, 'wb')
                txt_w.write(b'\n'.join(txt))
                txt_w.close()