from pycipher import Vigenere
from itertools import permutations
from math import log10


# NGRAM SCORE FUNCTION FROM http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/
class ngram_score(object):
    def __init__(self, ngramfile, sep=' '):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
        self.ngrams = {}
        file = open(ngramfile, "r")
        for line in file:
            key, count = line.split(sep)
            self.ngrams[key] = int(count)
        self.L = len(key)
        self.N = sum(self.ngrams.values())
        # calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key]) / self.N)
        self.floor = log10(0.01 / self.N)

    def score(self, text):
        ''' compute the score of text '''
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text) - self.L + 1):
            if text[i:i + self.L] in self.ngrams:
                score += ngrams(text[i:i + self.L])
            else:
                score += self.floor
        return score


def count(cip):
    let = [0] * 26
    for x in cip.upper():
        let[ord(x) - 65] = let[ord(x) - 65] + 1
    return let


def ic(cip):
    num = 0.0
    den = 0.0
    for val in count(cip):
        i = val
        num += i * (i - 1)
        den += i

    if den == 0.0:
        return 0.0
    else:
        return num / (den * (den - 1))


def seq(cip, per):
    cip = cip.lower()
    seqs = [""] * per
    for x in range(per):
        cnt = 0
        for y in cip:
            if (cnt + per - x) % per == 0:
                seqs[x] = seqs[x] + y
            cnt = cnt + 1

    return seqs


def space(txt, size):
    x = txt[0]
    txt = txt[1:]
    for y in txt:
        x = x + ' ' * (size - 1) + y
    return x


def calc(cip, init, rep):
    ave = [0.0] * (rep + 1)
    siz = len(cip) + 8
    print('%*sI.C.' % (siz + 15, ""))
    print("%-14s %-*s%-10f" % ('original:', siz, cip.lower(), ic(cip)))
    for x in range(init, rep + 1):
        print('if key were length ' + str(x) + ':')
        seqs = seq(cip, x)
        cnt = 1
        sum = 0.0
        for y in seqs:
            val = ic(y)
            print("sequence %3d:%*s%-*s%-10f" % (cnt, cnt, "", siz + 2 - cnt, space(y, x), val))
            sum = sum + val
            cnt = cnt + 1
        ave[x] = sum / x
        print('%*saverage: %-10f\n' % (siz + 6, "", ave[x]))
    print("period%10savg I.C." % (''))
    print("------------------------")
    for x in range(init, rep + 1):
        print("%2d:%20f" % (x, ave[x]))
    max_ave = max(ave)
    mpl = ave.index(max_ave)
    print("\nMost probable key length: " + str(mpl) + "\n I.C. = " + str(max_ave))
    return mpl


def fit(cip, key_len):
    fitness = ngram_score('quadgrams.txt')
    high = -9999999.0
    parent = ""
    perm_size = 3
    rng = int(key_len / perm_size)
    for x in range(rng):
        for y in permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZ', perm_size):
            key = parent[:x * perm_size] + ''.join(y) + 'A' * (key_len - perm_size * (x + 1))
            vig = Vigenere(key).decipher(cip)
            test = ""
            cnt = 0
            for z in vig:
                if cnt < 4 + (x * key_len):
                    test = test + z
                cnt = cnt + 1
                if cnt == key_len:
                    cnt = 0
            test_score = fitness.score(test)
            if test_score > high:
                high = test_score
                parent = key
                print(key + " score: " + str(test_score))
        high = -9999999.0
        print("\nCurrent Parent: " + parent+ "\n")
    print("\nFinal Key: " + parent)


def main():
    inp = input("Enter Vigenere Cipher: ")
    msl = input("Enter Max Sequence Length: ")
    res = calc(inp, 2, int(msl))
    fit(inp, res)


main()
