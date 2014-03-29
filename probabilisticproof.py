#!/usr/bin/env ipython

"""
--------------------------------------------------------------------------
"A single bit change in the pre-image changes, on the average, half of the 
bits in the hash value" --Bruce Schneier
--------------------------------------------------------------------------

The purpose of this program is to test the accuracy of this statement for 
various cryptograhic hash functions. 

"""

import os
import random
import binascii
import numpy as np
from Crypto.Hash import *
from Crypto.Hash import __all__ as allhash

del(allhash[0])
allhashlen=[128,# MD2
            128,# MD4
            128,# MD5
            160,# RIPEMD-160
            160,# SHA
            224,# SHA-224
            256,# SHA-256
            384,# SHA-384
            512]# SHA-512

if len(allhashlen)!=len(allhash):
    raise ValueError('List of hashes and list of hash lengths are mismatched.')
    exit()

FILESIZE = 1000
TRIALS = 10000

r=random.SystemRandom()

def converttograycode(a):
    """
    https://en.wikipedia.org/wiki/Gray_code#Constructing_an_n-bit_Gray_code
    """
    return (a)^((a)/2) 

def gensourcebits(fsize=FILESIZE):
    rab = r.getrandbits(fsize)
    while len(bin(rab)[2:]) < fsize:
        rab <<= 1
    return rab


def makenumbers(fs=FILESIZE,batch=TRIALS):
    rb=gensourcebits()
    rbg=converttograycode(rb)

    d = {}
    for i in range(rb, rb+batch):
        grayi = bin(converttograycode(i))
        for hfuncname in allhash:
            d.setdefault(grayi,[]).append(eval("%s.new()" % hfuncname))
        for j in d[grayi]:
            j.update(grayi)
    return d



def getalldigestsoftype(hashtypeindex, mydict):
    hashesoftype = []
    for binnum in mydict:
        hashfunclist = mydict[binnum]
        hashofbinnum = hashfunclist[hashtypeindex].digest()
        binhashofbinnum = hashstr2binstr(hashofbinnum, allhash[hashtypeindex])
        hashesoftype.append(binhashofbinnum)
    return hashesoftype


def hashstr2binstr(escapedxsevery3rdchar, typeofhash):
    if typeofhash not in allhash:
        raise ValueError("We don't test hashes of type %s" % typeofhash)
    intermstr = binascii.hexlify(escapedxsevery3rdchar)
    intermstr = int('0x' + intermstr, 0)
    str1s0s = bin(intermstr)[2:]
    howbig=allhashlen[ allhash.index(typeofhash) ]
    while len(str1s0s) < howbig:
        str1s0s = '0'+str1s0s
    return str1s0s


def getsinglebitdiff(binstr1, binstr2):
    if len(binstr1) != len(binstr2):
        raise ValueError("Strings are of uneven size") # See hashstr2binstr
    else:
        a = 0
        length = len(binstr1)
        for i in xrange(length):
            if binstr1[i] == binstr2[i]:
                a+=1
            else: pass
        percentchanged = (a+0.)/length
        return percentchanged


def getavgbitdiff(hashbindigestlist):
    bitdiffs = []
    for k in xrange( len(hashbindigestlist) - 1 ):
        numbitschanged=getsinglebitdiff(hashbindigestlist[k], \
                                        hashbindigestlist[k+1])
        bitdiffs.append(numbitschanged)
    return np.array(bitdiffs).mean()


def printresults(resultsdict):
    for hash in resultsdict:
        abd = getavgbitdiff(resultsdict[hash])
        print "Changing 1 bit in the preimage changes {:.2%} of the bits in the {} hash.".format(abd, hash)


def main():
    numsandhashes = makenumbers()
    hashtypes = dict((allhash[h],getalldigestsoftype(h, numsandhashes)) for \
                h in range(len(allhash)))
    printresults(hashtypes)
    exit()


if __name__ == '__main__':
    main()

