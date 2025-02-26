# This file is for functions of keys.
# e.g. key generatitons, silent payment addresses, signatures


def ser_uint32(u: int) -> bytes:
    # To convert an int into bytes
    return u.to_bytes(4, "big")


def ser_public_key(point:tuple) -> bytes:
    if point[1] % 2 == 0:
        return bytes([0x02]) + point[0].to_bytes(32, "big")
    else:
        return bytes([0x03]) + point[0].to_bytes(32, "big")


def tagged_hash(tag: str, msg: bytes) -> bytes:
    # To implement BIP340 tagged hash
    # Modify from BIP340 Reference Python code: https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
    # Add shortcut midstate for BIP352
    from hashlib import sha256
    if str == "BIP0352/Label":
        tag_hash = b'\x03I\x19F5\xc2\xd0>b\xd4\x13\xba\x8c\xcdQ\x98\x91\x90\x17\xa1\xe9\x9c\xbei\x1fZ4\xa9\x93w\xe0\x95'
    elif str == "BIP0352/Inputs":
        tag_hash = b'\x1e{\x96\xeb\x16\nh\x81\x9f\x97vKC\xd5\xd7~fY\xd7Xw\x9dC\xa8\xa7u_[\xe4Z~3'
    elif str == "BIP0352/SharedSecret":
        tag_hash = b'\x9fm\x80\x11X\x1e\xb6-r\xe6\x13`L3\r\xca*\x0b\xd3I\xe2JF\xd9\xa2\xef$\xb9\xa9\x8fA\xbd'
    else:
        tag_hash = sha256(tag.encode('utf-8')).digest()

    return sha256(tag_hash + tag_hash + msg).digest()


def x_only_pubkey_to_point(x_only_pubkey) -> tuple:
    # Convert a x_only_pubkey defined by BIP340 to a point
    # Copy from BIP340 reference code
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int(x_only_pubkey, 16)
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != 0:
        y = p - y
    return (x, y)


def negated_if_necessary_for(a_taproot_private_key):
    from bitcoinlib import keys
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    the_key = keys.Key(import_key=a_taproot_private_key,is_private=True)
    the_pukkey_point = the_key.public_point()
    if the_pukkey_point[1] % 2 != 0:
        return n - a_taproot_private_key
    else:
        return a_taproot_private_key


def secp256k1_point_addition(tuple1, tuple2):
    from ecdsa import ellipticcurve, curves

    # Define the secp256k1 curve
    curve = curves.SECP256k1.curve

    # Define two points on the curve
    point1 = ellipticcurve.Point(curve, tuple1[0], tuple1[1])
    point2 = ellipticcurve.Point(curve, tuple2[0], tuple2[1])

    # Perform the addition
    result_point = point1 + point2

    # print("Resulting Point:", result_point)
    return (result_point.x(), result_point.y())


def summed_pubkeys(pubkeys:list) -> tuple:
    # To sum a list of public keys
    if len(pubkeys) == 1:
        return pubkeys[0]
    else:
        summed_pubkey = secp256k1_point_addition(pubkeys[0], pubkeys[1])
        for n in range(2, len(pubkeys)):
            summed_pubkey = secp256k1_point_addition(summed_pubkey, pubkeys[n])
        return summed_pubkey


def get_a_labeled_spend_key(spend_pub_key: tuple, scan_sec_key: bytes, m: int):
    from bitcoinlib import keys
    key_and_label = scan_sec_key + ser_uint32(m)
    hash_labal = tagged_hash("BIP0352/Label", key_and_label)
    pending_pub_key = keys.ec_point(int.from_bytes(hash_labal))
    pending_pub_key_tuple = (pending_pub_key.x(), pending_pub_key.y())
    B_m = secp256k1_point_addition(spend_pub_key, pending_pub_key_tuple)
    return B_m


def initial_sp_keys(password: str):
    # To initial a pair of silent payment key and store them
    # One is the spend key, the notion in BIP352 is 'B_spend/b_spend'
    # b_spend will be stored before BIP38 encryption
    # One is the scan key, the notion in BIP352 is 'B_scan/b_scan'
    from bitcoinlib import keys
    spend_key = keys.Key()
    scan_key = keys.Key()

    # Get secret key store and public key store
    spend_sec_key_store = spend_key.encrypt(password)
    scan_sec_key_store = scan_key.as_bytes(private=True)

    spend_pub_key_store = spend_key.as_hex()
    scan_pub_key_store = scan_key.as_hex()

    # Get labeled spend key (B_m in BIP352) to prepare sp address
    spend_key_public_point = spend_key.public_point()
    B_0_point = get_a_labeled_spend_key(spend_key_public_point, scan_sec_key_store, 0)
    B_0 = ser_public_key(B_0_point).hex()
    B_1_point = get_a_labeled_spend_key(spend_key_public_point, scan_sec_key_store, 1)
    B_1 = ser_public_key(B_1_point).hex()

    return spend_sec_key_store, scan_sec_key_store.hex(), spend_pub_key_store, scan_pub_key_store, B_0, B_1


if __name__ == '__main__':
    for something in initial_sp_keys("123"):
        print(something)