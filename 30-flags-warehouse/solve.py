
with open('./flags.txt') as f:
    for l in f.readlines():
        if len(l) != 28:
            print(l)
