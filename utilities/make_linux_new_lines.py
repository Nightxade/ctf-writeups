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

            if category == 'index.md':
                txt = open(category_path, 'rb').read().replace(b'\r\n', b'\n')
                txt_w = open(category_path, 'wb')
                txt_w.write(txt)
                txt_w.close()


            # for writeup in os.listdir(category_path):
            #     writeup_path = os.path.join(category_path, writeup)

            #     txt = open(writeup_path, 'rb').read().replace(b'\r\n', b'\n')
            #     txt_w = open(writeup_path, 'wb')
            #     txt_w.write(txt)
            #     txt_w.close()