import os

PATH = "_writeups"

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

                txt = open(writeup_path, 'rb').read().split(b'\n')
                tag_i = list(filter(lambda a: b'tags: ' == a[1][:6], enumerate(txt)))[0][0]
                txt[tag_i] = b'tags: ' + ctf.encode() + b' ' + txt[tag_i][6:]
                # txt_w = open(writeup_path, 'wb')
                # txt_w.write(b'\n'.join(txt))
                # txt_w.close()
                print(txt[tag_i])