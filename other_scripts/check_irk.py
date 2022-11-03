#!/usr/bin/env python3

from Crypto.Cipher import AES


def e(irk, plaintext):
    if len(plaintext) != 16:
        raise ValueError

    arr1 = bytearray(irk)
    arr1.reverse()
    key = bytes(arr1)

    arr2 = bytearray(plaintext)
    arr2.reverse()
    pt = bytes(arr2)

    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pt)

    arr3 = bytearray(ct)
    arr3.reverse()
    result = bytes(arr3)

    return result


def ah(key, prand):
    r = prand + (b"\x00" * 13)
    h = e(key, r)

    return h[0:3]


def parse_mac(addr):
    addr = addr.replace(":", "")
    arr = bytearray(bytes.fromhex(addr))
    arr.reverse()
    return bytes(arr)


def main():
    # Example IRK and RPA
    # Assuming we've already bonded with the Smart Tag, IRK can be found in
    # /var/lib/bluetooth/<MAC address of laptop>/<MAC address of smarttag>/info

    irk_str = "bca6db301dd2d689c9fab97d6808d956"
    irk = bytes.fromhex(irk_str)

    # RPA: 72:13:e3:7c:d9:40
    # Note that the actual bytes are in the 'little-endian' order
    rpa_str = "53:B9:0C:AB:28:BE"
    rpa = parse_mac(rpa_str)
    rpa_prand = rpa[3:6]
    rpa_hash = rpa[0:3]

    hash = ah(irk, rpa_prand)

    print("Resolving RPA %s using IRK %s: " % (rpa_str, irk_str))
    print("- prand:             " + rpa_prand.hex())
    print("- Hash from address: " + rpa_hash.hex())
    print("- Computed hash:     " + hash.hex())

    if hash == rpa_hash:
        print("Address resolution succeeded")
    else:
        print("Address resolution failed")


if __name__ == "__main__":
    main()
