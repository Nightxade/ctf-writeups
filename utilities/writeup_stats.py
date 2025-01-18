import os

PATH = "_writeups"

total_wc = 0
total_writeups = 0
longest_writeups = []

for year in os.listdir(PATH):
    year_path = os.path.join(PATH, year)

    if year == '_site' or not os.path.isdir(year_path):
        continue

    for ctf in os.listdir(year_path):
        ctf_path = os.path.join(year_path, ctf)

        # print(f'\n\n{ctf}:')

        for category in os.listdir(ctf_path):
            category_path = os.path.join(ctf_path, category)

            if category == 'index.md': continue

            for writeup in os.listdir(category_path):
                writeup_path = os.path.join(category_path, writeup)
                total_writeups += 1

                txt = open(writeup_path, 'rb').read().split(b'\n')
                txt = list(map(lambda s: s.strip(), txt))
                line_ind = len(txt) - txt[::-1].index(b'---')
                txt = txt[line_ind+1:]
                
                curr_wc = 0
                counting = True
                for line in txt:
                    if line[:3] == b'```' or line[-3:] == b'```':
                        counting = not counting
                    if not counting:
                        continue

                    curr_wc += line.count(b' ') + 1

                total_wc += curr_wc
                # print(f'{curr_wc},{writeup}', end=' ')

                longest_writeups.append((curr_wc, f'{ctf}/{writeup}'))
                if len(longest_writeups) > 10:
                    longest_writeups.remove(min(longest_writeups, key=lambda f: f[0]))

# print('\n')
print("Number of writeups:", total_writeups)
print("Average WC:", '{:.03f}'.format(total_wc/total_writeups))
print("Total WC:", total_wc)
print("Longest Writeups:")
for wc, path in sorted(longest_writeups, reverse=True):
    print(f'    {path}: {wc}')