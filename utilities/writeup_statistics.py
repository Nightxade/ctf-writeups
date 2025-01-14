import os

def count_files(path):
    count = 0
    for root, dirs, files in os.walk(path):
        count += sum([1 if (file[-3:] == ".md" and file != "index.md") else 0 for file in files])
    return count

def count_words_chars(path):
    wc = 0
    cc = 0
    for root, dirs, files in os.walk(path):
        for file in files:
            if file[-3:] == ".md" and file != "index.md":
                f = open(root.replace('\\','/') + '/' + file, 'rb').read().replace(b'\n', b'')
                cc += len(f)
                wc += len(f.split(b' '))
    return wc, cc

PATH = "_writeups"
file_count = count_files(PATH)
word_count = count_words_chars(PATH)
print(file_count)
print(word_count)