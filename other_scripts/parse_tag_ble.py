# This script contains the reverse engineered algorithm that SmartThings uses to parse the BLE advertisement of a SmartTag
# (c) 2022 Tingfeng Yu


# byte array to string...
def b(bArr):
    sb = ""
    for b2 in bArr:
        sb += "0123456789abcdef"[(b2 & 240) >> 4]
        sb += "0123456789abcdef"[b2 & 15]
    print(sb)
    return


def lower4bits(b):
    mask = 15
    return b & mask


def upper4bits(b):
    mask = 240
    return b & mask


def parsePacket(bArr):
    i5 = upper4bits(bArr[0]) >> 4  # version
    i6 = (lower4bits(bArr[0]) >> 3) & 1  # advertisementType 00 or 01
    i7 = lower4bits(bArr[0]) & 7  # tagState
    i8 = (bArr[3] << 16) + (bArr[2] << 8) + bArr[1]  # aging counter
    bArr2 = bArr[4:12]  # 8-byte privacyID
    a = bArr2.hex()
    i9 = upper4bits(bArr[12]) >> 4  # * region Id
    i10 = (lower4bits(bArr[12]) >> 3) & 1  # encryptionFlag
    i11 = (lower4bits(bArr[12]) >> 2) & 1  # uWBFlag
    i12 = lower4bits(bArr[12]) & 3  # battery level
    bArr3 = bArr[13:16]  # reserved
    bArr4 = bArr[16:20]  # signature

    # check privacy ID pool to see if the 8-byte privacy ID is valid
    #           byte[] j3 = a.h().j(bArr, a);
    # check whether the privacyID is outdated for the current aging counter I suppose?
    #            boolean m = a.h().m(a, i8);
    # bArr4 = b(bArr4)
    print(
        "[tagState]"
        + str(i7)
        + "[advertisementType]"
        + str(i6)
        + "[agingCounter]"
        + str(i8)
        + "[privacyId]"
        + a
        + "[encryptionFlag]"
        + str(i10)
        + "[uWBFlag]"
        + str(i11)
        + "[batteryLevel]"
        + str(i12)
        + "[signature]"
        + bArr4.hex()
        + "[reserved]"
        + bArr3.hex()
    )
    print("[version]" + str(i5) + "[regionID]" + str(i9))
    pass


adv = bytes.fromhex("156bfa00c84062b28f00e260c3000000ad018b47")
parsePacket(adv)
