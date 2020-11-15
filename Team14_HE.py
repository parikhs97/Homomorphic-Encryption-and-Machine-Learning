# -*- coding: utf-8 -*-
"""
Created on Sat Oct  3 17:50:19 2020

@author: Shreya Parikh 
"""
import numpy as np
from numpy.polynomial import polynomial as poly


def polymul(x, y, modulus, polyMod):
    res = poly.polymul(x, y)
    res = poly.polydiv(res % modulus, polyMod)
    res = np.round(res[1] % modulus)
    res = np.int64(res)
    return res

def polyadd(x, y, modulus, polyMod):
    res = poly.polyadd(x, y)
    res = poly.polydiv(res % modulus, polyMod)
    res = np.round(res[1] % modulus)
    res = np.int64(res)
    return res

def keygen(size, modulus, polyMod):
    #Generate a public and secret keys
    #Generates a polynomial with coeffecients in [0, 1]
    sk = np.random.randint(0, 2, size, dtype=np.int64)
    #Generates a polynomial with coeffecients being integers in Z_modulus
    a = np.random.randint(0, modulus, size, dtype=np.int64)
    #Generates a polynomial with coeffecients in a normal distribution
    e = np.int64(np.random.normal(0, 2, size))
    t = polymul(-a, sk, modulus, polyMod)
    b = polyadd(t, -e, modulus, polyMod)
    return (b, a), sk


def encrypt(pk, size, q, t, polyMod, pt):
    #Encrypt an integer.   
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m  % q
    #Generates a polynomial with coeffecients in a normal distribution
    e1 = np.int64(np.random.normal(0, 2, size))
    e2 = np.int64(np.random.normal(0, 2, size))
    #Generates a polynomial with coeffecients in [0, 1]
    u = np.random.randint(0, 2, size, dtype=np.int64) 
    polyMulValue = polymul(pk[0], u, q, polyMod)
    polyAddValue = polyadd(polyMulValue,e1, q, polyMod)
    ct0 = polyadd(polyAddValue,scaled_m, q, polyMod)   
    polyMulValue2 = polymul(pk[1], u, q, polyMod)
    ct1 = polyadd(polyMulValue2,e2, q, polyMod)
    
    return (ct0, ct1)


def decrypt(sk, size, q, t, polyMod, ct):
    #Decrypt a ciphertext 
    polyMul = polymul(ct[1], sk, q, polyMod)
    scaled_pt = polyadd(polyMul,ct[0], q, polyMod)
    decrypted_poly = np.round(scaled_pt * t / q) % t
    res = int(decrypted_poly[0])
    return res

def addPlain(ct, pt, q, t, polyMod):
    #Add a ciphertext and a plaintext.    
    size = len(polyMod) - 1
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    delta = q // t
    scaled_m = delta * m  % q
    new_ct0 = polyadd(ct[0], scaled_m, q, polyMod)
    res = (new_ct0, ct[1])
    return res


def mulPlain(ct, pt, q, t, polyMod):
    #Multiply a ciphertext and a plaintext.
    size = len(polyMod) - 1
    # encode the integer into a plaintext polynomial
    m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    new_c0 = polymul(ct[0], m, q, polyMod)
    new_c1 = polymul(ct[1], m, q, polyMod)
    res = (new_c0, new_c1)
    return res

# Scheme's parameters
# polynomial modulus degree
n = 2**4
# ciphertext modulus
q = 2**15
# plaintext modulus
t = 2**8
# polynomial modulus
polyMod = np.array([1] + [0] * (n - 1) + [1])
# Keygen
publicKey, secretKey = keygen(n, q, polyMod)
# Encryption


pt1, pt2 = 73, 20

print("Plaintext 1 : " + str(pt1))
print("\nPlaintext 2 : " + str(pt2))



cst1, cst2 = 7, 5
ct1 = encrypt(publicKey, n, q, t, polyMod, pt1)
ct2 = encrypt(publicKey, n, q, t, polyMod, pt2)

print("\nCiphertext ct1({}):".format(pt1))
print("")
print("ct1_0:", ct1[0])
print("ct1_1:", ct1[1])
print("")
print("Ciphertext ct2({}):".format(pt2))
print("")
print("ct2_0:", ct2[0])
print("ct2_1:", ct2[1])
print("")

# Evaluation
ct3 = addPlain(ct1, cst1, q, t, polyMod)
ct4 = mulPlain(ct2, cst2, q, t, polyMod)

print("Encrypted ct3(ct1 + {}): {}".format(cst1, ct3))
print("")
print("Encrypted ct4(ct2 * {}): {}".format(cst2, ct4))
print("")

# Decryption
decrypted_ct3 = decrypt(secretKey, n, q, t, polyMod, ct3)
decrypted_ct4 = decrypt(secretKey, n, q, t, polyMod, ct4)

print("Decrypted ct3(ct1 + {}): {}".format(cst1, decrypted_ct3))
print("Decrypted ct4(ct2 * {}): {}".format(cst2, decrypted_ct4))