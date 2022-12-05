# HCracker Plugin made for H3x0r.
# Author: SecVirus
# Version: 1.0.0v

# Not Completed yet (All the below code are under development).


import argparse
import hashlib
import os.path
from argparse import ArgumentParser

class Cracker:
    def __init__(self, wordlists: list, hashes: list, threads: int = 1):
        if len(wordlists) < 1:
            return
        self.wordlists = list(set(wordlists))
        self.hashes = hashes
        self.threads = threads

        self.default_type = "md5"

        self.parser = ArgumentParser()
        self.parser.add_argument("-t", "--type", type=str, required=False, default=self.default_type)
        self.parser.add_argument("-w", "--wordlist", type=str, required=True)
        print(self.parser)

        self.cracked = 0

    @staticmethod
    def perc(all, part, n_after: int = 2):
        """
        :param all:
        :param part:
        :param n_after: numbers after the point
        :return:
        """
        return (f"%.{n_after}f" % ((part / all) * 100)) + "%"

    def crack(self):
        for wordlist in self.wordlists:
            if os.path.exists(wordlist):
                if os.path.isfile(wordlist):
                    wordlist_name = os.path.split(wordlist)[-1]
                    print(f"[#] Cracking with '%s' in progress.." % wordlist_name)
                    with open(wordlist, "r", errors="ignore") as file:
                        file_words = file.readlines()
                        if len(file_words) > 0:
                            for (index, word) in enumerate(file_words):
                                word = word.strip()
                                print("\r[+] Cracked: [%s/%s] - [%s/%s] - %s" % (self.cracked, len(self.hashes), (index + 1), len(file_words), self.perc(all=len(file_words), part=index)), end='\r')
                                print("\r", end='')

                                hash = hashlib.md5(word.encode(errors="ignore")).hexdigest()
                                if hash in self.hashes:
                                    print(f"*** {word}:{hash}")
                                    self.cracked += 1
                                    if self.cracked == len(self.hashes):
                                        break
                    file.close()
                    if not self.cracked == len(self.hashes):
                        print("\n\nCouldn't crack:\n")
                        for hash in self.hashes:
                            print(hash)


cracker = Cracker(wordlists=["rockyou.txt"], hashes=["6c35adaf16980f4f3de7d44cd0f3b378", "22dbe53cc913ca5be5936b8d8996e419", "820afb7f8e1b52fdbde85ae38f8eb381"])
# cracker.crack()