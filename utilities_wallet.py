def create_a_rg_wallet(abslute_wallet_path, wallet_password, rpc):
    try:
        rpc.createwallet(abslute_wallet_path, False, False, wallet_password, False, True, False)
    except:
        pass
        

def know_a_rg_wallet_balance(wallet_rpc_connection):
    return str(wallet_rpc_connection.getbalance()) + " BTC"


def get_a_receving_address(wallet_rpc_connection):
    return wallet_rpc_connection.getnewaddress("", "bech32")

def send_a_rg_payment_from_a_rg_wallet(tx_tuple, wallet_rpc_connection):
    from decimal import Decimal
    result_tx_id = wallet_rpc_connection.sendtoaddress(tx_tuple[0], Decimal(tx_tuple[1]), "", "",
                                                       False, True, tx_tuple[2])
    return result_tx_id


def sp_allowed_input_as_a(utxo) -> bool:
    script_pubkey = utxo["scriptPubKey"]
    # if it is a P2TR output
    if len(script_pubkey) == 68 and script_pubkey[:4] == "5120":
        return True
    # if it is a P2wPKH output
    elif len(script_pubkey) == 44 and script_pubkey[:4] == "0014":
        return True
    # if it is a P2PKH output
    elif len(script_pubkey) == 50 and script_pubkey[:6] == "76a914" and script_pubkey[-4:] == "88ac":
        return True
    # if it is a P2SH-P2WPKH output
    elif len(script_pubkey) == 46 and script_pubkey[:4] == "a914" and script_pubkey[-2:] == "87":
        if utxo["redeemScript"][:4] == "0014":
            return True
        else:
            return False
    else:
        return False


def collect_sp_allowed_coin_and_balance_in_a_rg_wallet_by(wallet_rpc_connection):
    from decimal import Decimal
    entire_coin_set = wallet_rpc_connection.listunspent()
    sp_allowed_coin_set = []
    sp_allowed_balance = Decimal(0)
    for coin in entire_coin_set:
        if sp_allowed_input_as_a(coin) and coin["spendable"] is True:
            sp_allowed_coin_set.append(coin)
            sp_allowed_balance += coin["amount"]
        else:
            pass
    
    return sp_allowed_coin_set, sp_allowed_balance


def solve_output_type_by(address):
    # note that it can only solve for sp allowed output
    if address[0] == "1":
        return "P2PKH"
    elif address[0:4] == "bc1q":
        return "P2WPKH"
    elif address[0:4] == "bc1p":
        return "P2TR"
    else:
        return "P2SH-P2WPKH"


def size_in_vbytes_table_of(address_as_an_input):
    from decimal import Decimal
    if address_as_an_input[0] == "1":
        return Decimal(148)
    elif address_as_an_input[0:4] == "bc1q":
        return Decimal(68)
    elif address_as_an_input[0:4] == "bc1p":
        return Decimal(57.5)
    else:
        return Decimal(85)


def parse_sp_address(sp_address):
    import bech32m
    if sp_address[0:2] == "sp":
        version, pubkey_data = bech32m.decode("sp", sp_address)
    elif sp_address[0:3] == "tsp":
        version, pubkey_data = bech32m.decode("tsp", sp_address)
    else:
        return False

    if version != "0" or len(pubkey_data) != 66:
        return False
    else:
        return pubkey_data


def send_a_sp_payment_from_a_rg_wallet(input_coins, payment_intention, wallet_rpc_connection):
    # First, prase sp address and ensure it is valid
    sp_pubkey = parse_sp_address(payment_intention[0])
    if sp_pubkey is False:
        return "sp_address_error"
    else:
        B_scan = sp_pubkey[0:33]
        B_m = sp_pubkey[33:]

    # Then, get the input_hash and sender_private_key from inputs selected by the user
    from utilities_scan import get_bip352_outpoint
    from utilities_keys import negated_if_necessary_for, tagged_hash, ser_uint32, ser_public_key
    from utilities_keys import secp256k1_point_addition
    from bitcoinlib import keys
    input_outpoints = []
    sender_private_key = 0
    pending_transaction_input = []
    for coin in input_coins:
        pending_transaction_input.append({"txid":coin["txid"], "vout":coin["vout"]})
        input_outpoints.append(get_bip352_outpoint(coin["txid"], coin["vout"]))
        input_private_key = wallet_rpc_connection.dumpprivkey(coin["address"])
        # negate the private key for taproot output, if it cannot produce a point with even y
        if coin["adress"][0:4] == "bc1p":
            input_private_key = negated_if_necessary_for(input_private_key)
        sender_private_key += input_private_key
    if sender_private_key == 0:
        return "input_privete_key_error"

    smallest_outpoint = min(input_outpoints)
    sender_key = keys.Key(import_key=sender_private_key, is_private=True)
    sender_pubkey_point = sender_key.public_point()
    ser_sender_pubkey = (bytes([0x04]) + sender_pubkey_point[0].to_bytes(32, 'big') +
                         sender_pubkey_point[1].to_bytes(32, 'big'))
    input_hash = tagged_hash("BIP0352/Inputs", smallest_outpoint + ser_sender_pubkey)

    # generate ecdh_shared_secret, as a tuple
    B_scan_key = keys.Key(import_key=B_scan)
    B_scan_key_point = B_scan_key.public_point()
    ecdh_shared_secret = keys.ec_point_multiplication(B_scan_key_point, int.from_bytes(input_hash) * sender_private_key)

    # generate t_k and responding taproot address
    k = 0
    t_k_bytes = tagged_hash("BIP0352/SharedSecret", ser_public_key(ecdh_shared_secret) + ser_uint32(k))
    t_k_int = int.from_bytes(t_k_bytes)
    if t_k_int == 0 or t_k_int > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F:
        return "t_k_error"
    B_m_key = keys.Key(import_key=B_m)
    B_m_point = B_m_key.public_point()
    t_k_key = keys.Key(import_key=t_k_int, is_private=True)
    t_k_point = t_k_key.public_point()
    P_mn = secp256k1_point_addition(B_m_point, t_k_point)
    taproot_script_pubkey = bytes([0x51, 0x20]) + P_mn(0).to_bytes()
    import bech32m
    taproot_address = ''
    if payment_intention[0][0:2] == "sp":
        taproot_address = bech32m.encode("bc", 1, taproot_script_pubkey)
    elif payment_intention[0][0:3] == "tsp":
        taproot_address = bech32m.encode("tbc", 1, taproot_script_pubkey)
    else:
        pass

    # send
    an_output = dict()
    an_output[taproot_address] = payment_intention[1]
    pending_transaction_output = list()
    pending_transaction_output.append(an_output)
    tx_hexstring = wallet_rpc_connection.createrawtransaction(pending_transaction_input, pending_transaction_output,
                                                              0, True,)
    result_tx_id = wallet_rpc_connection.signrawtransactionwithwallet(tx_hexstring)
    return result_tx_id


def create_a_sp_wallet(wallet_path, wallet_password):
    wallet_info = {}

    # set a unix time birthday
    import time
    unixtime = time.time()
    wallet_info["birthday"] = int(unixtime)

    from utilities_keys import initial_sp_keys
    spend_privkey_encrypted, scan_privkey, spend_pubkey, scan_pubkey, B_0, B_1 = initial_sp_keys(wallet_password)
    wallet_info["spend_private_key_encrypted"] = spend_privkey_encrypted
    wallet_info["scan_private_key"] = scan_privkey
    wallet_info["spend_pub_key"] = spend_pubkey
    wallet_info["scan_pub_key"] = scan_pubkey
    wallet_info["used_labeled_key"] = {"B_0":B_0, "B_1":B_1}
    wallet_info["unspend_transaction_outputs"] = list()
    wallet_info["spent_transaction_outputs"] = list()

    from os import path, mkdir
    import json
    mkdir(wallet_path)
    with open(path.join(wallet_path, "wallet_info"), "w") as f:
        json.dump(wallet_info, f)

    with open(path.join(wallet_path, "scanned_blocks"), "w") as f:
        f.write("scanned_blocks_hash, only grow\n")

    return wallet_info


def read_a_sp_wallet_info(wallet_path):
    from os import path
    import json
    with open(path.join(wallet_path, "wallet_info"), "r") as f:
        wallet_info = json.load(f)

    return wallet_info


def write_a_sp_wallet_info(wallet_path, wallet_info_dict):
    from os import path
    import json
    with open(path.join(wallet_path, "wallet_info"), "w") as f:
        json.dump(wallet_info_dict, f)


def check_if_tx_is_reorganized(tx_dict_list: list, node_rpc) -> list:
    cleaned_tx_dict_list = []
    for tx in tx_dict_list:
        if node_rpc.getblockhash(tx["confirm_height"]) == tx["confirm_hash"]:
            cleaned_tx_dict_list.append(tx)
    return cleaned_tx_dict_list


def read_scan_progress(wallet_path):
    from os import path
    with open(path.join(wallet_path, "scanned_blocks"), "r") as f:
        content = f.read()
    hash_list = content.split("\n")
    return hash_list


def clean_scan_progress(wallet_path):
    # to control the hash list's size, to present last 50 blocks scanned
    current_hash_list = read_scan_progress(wallet_path)
    if len(current_hash_list) <= 51:
        pass
    else:
        new_hash_list = current_hash_list[-50:]
        new_hash_list.insert(0, "scanned_blocks_hash, only grow")
        from os import path
        with open(path.join(wallet_path, "scanned_blocks"), "w") as f:
            f.write("\n".join(new_hash_list))


def get_possible_spending_key(sp_wallet_info):
    possible_key_list = [sp_wallet_info["spend_pub_key"]]
    for labeled_pubkey in sp_wallet_info["used_labeled_key"]:
        possible_key_list.append(sp_wallet_info["used_labeled_key"][labeled_pubkey])
    print(possible_key_list)
    return possible_key_list


def taproot_output_filter(a_raw_transaction_vout):
    taproot_outputs = [tx_output for tx_output in a_raw_transaction_vout
                       if tx_output["scriptPubKey"]["type"] == "witness_v1_taproot"]
    return taproot_outputs


def calcul_possible_x_only_key_by(possible_spending_key, current_t_k, import_modle):
    from utilities_keys import secp256k1_point_addition
    T_k = import_modle.Key(import_key=int.from_bytes(current_t_k))
    T_k_tuple = T_k.public_point()
    x_only_key_list = []
    for key_hex in possible_spending_key:
        key_itself = import_modle.Key(import_key=key_hex)
        key_point = key_itself.public_point()
        sum_key_point = secp256k1_point_addition(key_point, T_k_tuple)
        # sum_key_point contains x and y in int format
        # we need x_only_key in hex
        x_only_key_list.append(hex(sum_key_point[0]))
    return x_only_key_list


def check_taproot_output_match(target_taproot_output, calculed_possible_x_only_key_list):
    for n in range(0, len(calculed_possible_x_only_key_list)):
        if target_taproot_output["scriptPubKey"]["hex"][4:] == calculed_possible_x_only_key_list[n]:
            return n

    return False


def scan_blockchain_for_sp_wallet(wallet_info, wallet_path, network, rpc):
    from os import path
    import utilities_scan
    network_store = path.join('./sp-transactions-candidate', network)
    # if known time chain do not cover wallet entire life, let it go deeper
    utilities_scan.time_chain_go_deep(network_store, wallet_info["birthday"], rpc)
    # whatever, download blocks until known best
    # the function is able to avoid too much repeat verification
    utilities_scan.download_and_verify_blocks(network_store, rpc)
    # read time chain, go on
    time_chain = utilities_scan.read_time_chain(network_store)
    # now, check if already scanned transaction is reverted due to re-organization
    wallet_info["unspend_transaction_outputs"] = check_if_tx_is_reorganized(wallet_info["unspend_transaction_outputs"],
                                                                            rpc)
    write_a_sp_wallet_info(wallet_path, wallet_info)

    # then, based on scanned block record, start to scan blocks
    # the record is design to be as full as possible, every scanned block will leave a hash entry
    # including those been re-organized
    # we read time chain in reverse-order, to determine scan task
    # once we find a block hash is in record, means older blocks have been scanned, so stop
    scan_progress = read_scan_progress(wallet_path)
    scan_task = []
    while len(time_chain) > 0:
        newest_time_signal = utilities_scan.prase_time_signal(time_chain.pop())
        the_block_hash = newest_time_signal[1]
        if the_block_hash not in scan_progress:
            scan_task.insert(0, newest_time_signal)
        else:
            break

    from bitcoinlib import keys
    from utilities_keys import tagged_hash, ser_uint32, ser_public_key
    possible_key = get_possible_spending_key(wallet_info)
    for entry in scan_task:
        the_block_hash = entry[1]
        block_height = entry[0]
        eligible_tx_list = utilities_scan.read_eligible_txs_from(network_store, str(block_height))
        print("scanning silent payments for you in the block in height {}".format(block_height))
        for one_tx in eligible_tx_list:
            # print(one_tx)
            # every one_tx contains txid, input_hash, and sender key(A)
            raw_tx_outputs = rpc.getrawtransaction(one_tx[0], True, the_block_hash)["vout"]
            taproot_outputs = taproot_output_filter(raw_tx_outputs)
            sender_key_point = one_tx[2]
            input_hash_int = int(one_tx[1], 16)
            scan_privkey_int = int(wallet_info["scan_private_key"], 16)
            ecdh_shared_secret = keys.ec_point_multiplication(sender_key_point, input_hash_int * scan_privkey_int)

            k = 0
            t_k = tagged_hash("BIP0352/SharedSecret",
                              ser_public_key(ecdh_shared_secret) + ser_uint32(k))
            possible_x_only_key = calcul_possible_x_only_key_by(possible_key, t_k, import_modle=keys)
            for one_output in taproot_outputs:
                match_result = check_taproot_output_match(one_output, possible_x_only_key)
                if match_result is False:
                    continue
                else:
                    # we get an interested taproot output, let's put it into wallet
                    a_coin = dict()
                    a_coin["txid"] = one_tx[0]
                    a_coin["vout"] = one_output["n"]
                    a_coin["amount"] = one_output["value"]
                    a_coin["t_k"] = t_k
                    a_coin["spendable_pubkey"] = possible_key[match_result]
                    a_coin["address"] = one_output["scriptPubKey"]["address"]
                    a_coin["confirm_height"] = block_height
                    a_coin["confirm_hash"] = the_block_hash
                    wallet_info["unspend_transaction_outputs"].append(a_coin)
                    write_a_sp_wallet_info(wallet_path, wallet_info)
                    print("find a coin in silent payment for you.")
                    # then we need to update k etc.
                    k = k + 1
                    t_k = tagged_hash("BIP0352/SharedSecret",
                                      ser_public_key(ecdh_shared_secret) + ser_uint32(k))
                    possible_x_only_key = calcul_possible_x_only_key_by(possible_key, t_k, import_modle=keys)
        with open(path.join(wallet_path, "scanned_blocks"), "a") as f:
            f.write(the_block_hash + "\n")

    # finally, we need to check if these output is spent
    # (to be build)
    return wallet_info


def know_a_sp_wallet_balance(wallet_info):
    from decimal import Decimal
    balance = Decimal(0)
    for coin in wallet_info["unspend_transaction_outputs"]:
        balance += coin["value"]
    return str(balance)