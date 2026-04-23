"""RSA demo script: key generation, encryption, decryption.
"""

from math import gcd


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    limit = int(n ** 0.5) + 1
    sieve = [True] * (limit + 1)
    for i in range(2, limit):
        if sieve[i]:
            for j in range(i * i, limit, i):
                sieve[j] = False
    for i in range(3, limit, 2):
        if sieve[i] and n % i == 0:
            return False
    return True


def mod_inverse(a: int, m: int) -> int:
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("e and phi(n) are not coprime")
    if t < 0:
        t += m
    return t


def generate_keys(p: int, q: int, e: int):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p and q must be prime")
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi(n)")
    d = mod_inverse(e, phi)
    return (e, n), (d), phi


def encrypt(plaintext: str, public_key):
    e, n = public_key
    return [pow(ord(ch), e, n) for ch in plaintext]


def decrypt(ciphertext, private_key,n):
    d = private_key
    return "".join(chr(pow(c, d, n)) for c in ciphertext)


def main() -> None:
    plaintext = "19230323WentaoWang"
    p, q, e = 3557, 2579, 65537

    public_key, private_key, phi = generate_keys(p, q, e)
    ciphertext = encrypt(plaintext, public_key)
    recovered = decrypt(ciphertext, private_key,public_key[1])

    print("=== RSA ===")
    print(f"p = {p}, q = {q}")
    print(f"n = {public_key[1]}, phi(n) = {phi}")
    print(f"public key (e, n) = {public_key}")
    print(f"private key (d) = {private_key}")
    print(f"plaintext = {plaintext}")
    print(f"ciphertext = {ciphertext[:8]}")
    print(f"{ciphertext[8:]}")
    print(f"decrypted = {recovered}")


if __name__ == "__main__":
    main()
