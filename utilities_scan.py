def check_cross_set(list_1: list, list_2: list) -> bool:
    for elements in list_1:
        if elements in list_2:
            return True
        else:
            pass

    return False


def read_node_info():
    with open('sp.conf', 'r', encoding='utf-8') as f:
        words = f.read()
        lines = words.split('\n')
        node_info = {}
        for line in lines:
            if line.startswith('#') or line == '':  # Skip comments and empty lines
                continue
            key, value = line.replace(" ", "").split('=')
            node_info[key] = value
        return node_info


def get_bip352_outpoint(txid: str, vout: int) -> bytes:
    # To get the outpoint in BIP352 format
    # Passed txid is big-endian, change it to little-endian
    # Passed vout is int, change it to 4 bytes little-endian
    # Partly copy from BIP352 reference python code
    dixt = "".join(map(str.__add__, txid[-2::-2], txid[-1::-2]))
    outpoint = bytes.fromhex(dixt) + vout.to_bytes(4, 'little')
    if len(outpoint) == 36:
        return outpoint
    else:
        raise ValueError("Outpoint length is not 36 bytes")


def taproot_output_existence_check(all_of_tx_output):
    taproot_outputs = [entry for entry in all_of_tx_output if entry["scriptPubKey"]["type"] == "witness_v1_taproot"]
    if len(taproot_outputs) == 0:
        return False
    else:
        return taproot_outputs


def enrich_input_script_pubkey_for(tx, rpc):
    for entry in tx["vin"]:
        prev_txid = entry["txid"]
        index = entry["vout"]
        prev_tx = rpc.getrawtransaction(prev_txid, True)
        prev_out = prev_tx["vout"][index]
        entry["scriptPubKey"] = {"hex": prev_out["scriptPubKey"]["hex"], "type": prev_out["scriptPubKey"]["type"]}

    return tx


def extract_pubkey_for_taproot_input(taproot_input):
    witness_stack = taproot_input['txinwitness']
    # first, check whether annex exist
    if witness_stack[-1][0:2] == "50":
        witness_stack.pop(-1)

    if len(witness_stack) >= 2:
        control_block = witness_stack[-1]
        # when the internal key is NUMS point(H)
        if control_block[2:66] == "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0":
            return False

    # key spend and common script spend
    return taproot_input["scriptPubKey"]["hex"][4:]


def eligible_transactions_check_by(transaction_vin: list) -> bool:
    # To filter silent payments
    # 1. Should have at least one taproot output
    # already complete, so we just need below
    # 2. Should have at least one input which is public-key-extractable
    # include: P2TR, P2WPKH, P2SH-P2WPKH, P2PKH
    # 3. Should not spend inputs with SegWit version > 1 
    # Return Ture or false

    # Check rule #3 at first
    from bitcoinlib import scripts
    tx_input_type = []
    for entry in transaction_vin:
        type_info = entry["scriptPubKey"]["type"]
        if type_info[0:7] == "witness":
            readable_script_pubkey = scripts.Script.parse_hex(entry["scriptPubKey"]["hex"])
            if readable_script_pubkey[0:4] != "OP_0" and readable_script_pubkey[0:4] != "OP_1":
                return False

        tx_input_type.append(type_info)

    # then rule #2
    part_allowed_types = ["witness_v1_taproot", "witness_v0_keyhash", "pubkeyhash"]
    if check_cross_set(part_allowed_types, tx_input_type) is True:
        # if there is at least one easy checked allowed script type in inputs
        return True
    else:
        # check if there is P2SH_P2WPKH input
        for n in range(0, len(tx_input_type)):
            if tx_input_type[n] == "scripthash":
                input_being_check = transaction_vin[n]
                input_scriptsig = scripts.Script.parse_hex(input_being_check['scriptSig']['hex'])
                input_witness = input_being_check['txinwitness']
                # P2SH_P2WPKH characteristic: contain 2 stack in scriptsig and 2 stack
                if len(input_scriptsig.serialize_list()) == 2 and len(input_witness) == 2:
                    return True
            else:
                continue
        # if not
        return False


def extract_input_hash_and_sender_key(transaction_vin: list):
    # for each eligable input, extract its pubkey, then sum them up
    # at the same time, fine the smallest outpiont
    # finally, return the summed pubkey, which is A in BIP352, and the smallest outpoint,
    # to procduce 'input_hash' in BIP352
    from bitcoinlib import keys
    from bitcoinlib import scripts
    outpoints = []
    pubkeys = []
    for entry in transaction_vin:
        the_outpoint = get_bip352_outpoint(entry['txid'], entry['vout'])
        outpoints.append(the_outpoint)

        if entry["scriptPubKey"]["type"] == "witness_v1_taproot":
            x_only_pubkey = extract_pubkey_for_taproot_input(entry)
            if x_only_pubkey is not False:
                from utilities_keys import x_only_pubkey_to_point
                the_point = x_only_pubkey_to_point(x_only_pubkey)
                pubkeys.append(the_point)
        elif entry["scriptPubKey"]["type"] == "witness_v0_keyhash":
            compressed_pubkey = entry['txinwitness'][1]
            the_pubkey = keys.Key(compressed_pubkey)
            the_point = the_pubkey.public_point()
            pubkeys.append(the_point)
        elif entry["scriptPubKey"]["type"] == "scripthash":
            input_scriptsig = scripts.Script.parse_hex(entry['scriptSig']['hex'])
            input_witness = entry['txinwitness']
            if len(input_scriptsig.serialize_list()) == 2 and len(input_witness) == 2:
                compressed_pubkey = input_witness[1]
                the_pubkey = keys.Key(compressed_pubkey)
                the_point = the_pubkey.public_point()
                pubkeys.append(the_point)
            else:
                pass
        elif entry["scriptPubKey"]["type"] == "pubkeyhash":
            input_scriptsig = scripts.Script.parse_hex(entry['scriptSig']['hex'])
            scriptsig_list = input_scriptsig.serialize_list()
            # check if it is a compressed pubkey
            if len(scriptsig_list[-1]) == 33:
                the_pubkey = scriptsig_list[-1]
                the_pubkey = keys.Key(the_pubkey)
                the_point = the_pubkey.public_point()
                pubkeys.append(the_point)
            else:
                pass
        else:
            pass

    if len(pubkeys) == 0:
        return False, False

    # find the smallest outpoint
    smallest_outpoint = min(outpoints)
    # sum up the pubkeys and get its uncompressed form
    from utilities_keys import summed_pubkeys, tagged_hash
    summed_pubkey = summed_pubkeys(pubkeys)
    summed_pubkey_bytes = bytes([0x04]) + summed_pubkey[0].to_bytes(32, 'big') + summed_pubkey[1].to_bytes(32, 'big')
    # calculate the input hash
    input_hash = tagged_hash("BIP0352/Inputs", smallest_outpoint + summed_pubkey_bytes)
    return input_hash, summed_pubkey


def deal_with_a_block(block_height: int, block_hash: str, rpc):
    # To get a block, collect eligible transactions in it
    # And extract sender key for every eligible transaction
    import time
    start_time = time.time()
    print("Downloading and dealing the block in height {} ...".format(str(block_height)))
    content = [block_hash]
    block = rpc.getblock(block_hash, True)
    tx_list = block['tx'][1:]
    for entry in tx_list:
        tx = rpc.getrawtransaction(entry, True, block_hash)
        taproot_outputs_in_tx = taproot_output_existence_check(tx["vout"])
        # first stage of BIP352 eligible tx check
        if taproot_outputs_in_tx is False:
            continue

        tx = enrich_input_script_pubkey_for(tx, rpc)
        if eligible_transactions_check_by(tx['vin']) is True:
            # extract reusable info: input hash and sender key
            # print(entry)
            input_hash, sender_key = extract_input_hash_and_sender_key(tx['vin'])
            if sender_key is not False:
                the_eligible_transaction = {"txid":entry, "input_hash":input_hash.hex(),
                                            "sender_key":sender_key, "taproot_outputs":taproot_outputs_in_tx}
                content.append(the_eligible_transaction)
        else:
            pass

    end_time = time.time()
    print("Done. Process time is {} s.".format(int(round(end_time - start_time))))
    return content


def read_time_chain(time_chain_store_loca) -> list:
    import json
    with open(time_chain_store_loca, 'r') as f:
        time_chain = json.load(f)

    return time_chain


def write_time_chain(time_chain_store_loca, time_chain: list):
    import json
    with open(time_chain_store_loca, 'w') as f:
        json.dump(time_chain, f)


def time_chain_complete(time_chain: list, start_height: int, end_height: int, rpc):
    # end_height block would not be included
    for n in range(start_height, end_height):
        print("Downloading header for the block in height {}".format(str(n)))
        block_hash = rpc.getblockhash(n)
        block_time_stamp = rpc.getblockheader(block_hash)['time']
        time_chain.append([n, block_hash, block_time_stamp])

    return time_chain


def initial_time_chain(rpc, time_chain_store_loca):
    zero_time_chain = []
    # Get the newest ten blocks, except the newest one
    best_block_height = rpc.getblockcount()
    zero_time_chain = time_chain_complete(zero_time_chain, best_block_height - 10, best_block_height, rpc)

    write_time_chain(time_chain_store_loca, zero_time_chain)

    return zero_time_chain


def update_time_chain(rpc, time_chain_store_loca, mode=0):
    # Mainly for dealing with time chain reorganization
    # Read the current time chain
    current_time_chain = read_time_chain(time_chain_store_loca)

    # Then, we need to revert re-organized time chain
    while True:
        youngest_time_signal = current_time_chain[-1]
        height = youngest_time_signal[0]
        signal_hash = youngest_time_signal[1]
        node_block_hash = rpc.getblockhash(height)
        if node_block_hash != signal_hash:
            current_time_chain.pop()
        else:
            break

    # Then, sync the time chain with our node
    highest = rpc.getblockcount()
    current_height = current_time_chain[-1][0]
    if current_height == highest:
        pass
    else:
        current_time_chain = time_chain_complete(current_time_chain, current_height, highest+1, rpc)

    if mode == 0:
        write_time_chain(time_chain_store_loca, current_time_chain)
    elif mode == 1:
        # remember manually write time_chian_file when using mode 1
        return current_time_chain


def verification_status(network_store, mode, writable_vefi_status):
    # Operations about a file named 'verification_status'
    # mode 0: check if the file exists, if not, create one
    # then, return the content
    # mode 1: write the input into the file
    import json
    from os import path
    if mode == 0:
        if not path.exists(path.join(network_store, 'verification_status')):
            with open(path.join(network_store, 'verification_status'), 'w') as f:
                json.dump({}, f)
            return {}
        else:
            with open(path.join(network_store, 'verification_status'), 'r') as f:
                veri_status = json.load(f)
            return veri_status
    elif mode == 1:
        with open(path.join(network_store, 'verification_status'), 'w') as f:
            json.dump(writable_vefi_status, f)
    else:
        pass


def download_and_verify_blocks(network_store, rpc):
    # According to best time chain, download blocks and extract eligible transactions
    # Once start, do not consider block reorganization
    # Via a verification_status dict/file, avoid too much repeat verification
    # Get the best time chain, but have not written to the file
    print("Start to update basic information to best state...")
    from os import path
    import pickle
    time_chain_file = path.join(network_store, "time_chian")
    time_chain = update_time_chain(rpc, time_chain_file, 1)
    veri_status = verification_status(network_store, 0, {})

    print("Start to download and verify blocks...")
    for entry in time_chain:
        height_str = str(entry[0])
        varification_count = veri_status.get(height_str)
        block_file = path.join(network_store, height_str)
        
        if varification_count == 2:
            continue
        elif varification_count is None:
            # Typecaliy, it means we never get block for this height
            # However, we need to consider the situation that the program is shutting down before write vari_status
            # And there is a monitor mode, which will download blocks without touching time_chain file
            # If the file is not exist, download it and skip followed verification
            if not path.exists(block_file):
                block_and_eligable_tx = deal_with_a_block(entry[0], entry[1], rpc)
                with open(block_file, 'wb') as f:
                    pickle.dump(block_and_eligable_tx, f)
                veri_status[height_str] = 0
                continue
            # If the file is exist, add verification status, then check if the block is reorganized 
            else:
                veri_status[height_str] = 0
                pass
        
        # check historically stored block is reorganized or not
        with open(block_file, 'rb') as f:
            block_content = pickle.load(f)
        block_hash = block_content[0]
        if entry[1] == block_hash:
            veri_status[height_str] += 1
        else:
            # means historically stored block is reorganized
            # overwrite new block to the file
            block_and_eligable_tx = deal_with_a_block(entry[0], entry[1], rpc)
            with open(block_file, 'wb') as f:
                pickle.dump(block_and_eligable_tx, f)
            veri_status[height_str] = 0

    # write updated time_chain and verification_status to file
    write_time_chain(time_chain_file, time_chain)
    verification_status(network_store, 1, veri_status)
    print("Update blocks to best known.")


def time_chain_go_deep(time_chain_file, sp_wallet_birthday, rpc):
    time_chain = read_time_chain(time_chain_file)

    # get history time chain if not exist
    oldest_time_signal = time_chain[0]
    oldest_height = oldest_time_signal[0]
    oldest_time_stamp = oldest_time_signal[2]
    while True:
        if oldest_time_stamp > sp_wallet_birthday:
            previous_blcok_height = oldest_height - 1
            previous_block_hash = rpc.getblockhash(previous_blcok_height)
            previous_block_time_stamp = rpc.getblockheader(previous_block_hash)['time']
            time_chain.insert(0, [previous_blcok_height,
                                                   previous_block_hash, previous_block_time_stamp])
            oldest_height = previous_blcok_height
            oldest_time_stamp = previous_block_time_stamp
        else:
            break
    write_time_chain(time_chain_file, time_chain)


def read_eligible_txs_from(network_store, block_height):
    from os import path
    import pickle
    with open(path.join(network_store, block_height), "rb") as f:
        content = pickle.load(f)

    # block_hash = content_lines[0]
    eligible_txs = content[1:]
    return eligible_txs