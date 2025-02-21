def time_str_to_unix(time_str):
    # time is a str in the format of 'yyyy-mm-dd'
    # We need to complete it and convert it to unix timestamp
    import time
    time_str = time_str + ' 00:00:00'
    time_array = time.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    time_stamp = int(time.mktime(time_array))
    return time_stamp


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


def extract_pubkey_for_taproot_input(taproot_input, taproot_script_pubkey):
    witness_stack = taproot_input['txinwitness']
    # first, check whether annex exist
    if witness_stack[-1][0:2] == "50":
        witness_stack.pop(-1)

    if len(witness_stack) >= 2:
        control_block = witness_stack[-1]
        # when the internal key is NUMS point(H)
        if control_block[2:66] == "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0":
            return False
    else:
        # key spend and common script spend
        return taproot_script_pubkey[4:]


def get_prevout_script_pubkey_and_type(prev_txid: str, index: int, rpc):
    prevtx = rpc.getrawtransaction(prev_txid, True)
    prevout = prevtx['vout'][index]
    script_pubkey_hex = prevout['scriptPubKey']['hex']
    script_pubkey_type = prevout['scriptPubKey']['type']
    return (script_pubkey_hex, script_pubkey_type)


def eligible_transactions_check_by(transaction_vout: list, input_script_pub_keys: list, transaction_vin: list) -> bool:
    # To filter silent payments
    # 1. Should have at least one taproot output
    # 2. Should have at least one input which is public-key-extractable
    # include: P2TR, P2WPKH, P2SH-P2WPKH, P2PKH
    # 3. Should not spend inputs with SegWit version > 1 
    # Return Ture or false
    output_count = 0
    output_number = len(transaction_vout)
    for output in transaction_vout:
        if output['scriptPubKey']['type'] == 'witness_v1_taproot':
            break
        else:
            output_count += 1
    if output_count == output_number:
        # if there is no taproot outputs
        return False

    # Then we need to check input script pubkey
    from bitcoinlib import scripts
    input_types = []
    for script_pubkey_tuple in input_script_pub_keys:
        # First, check if there is input spending segwit version > 1
        input_script_type = script_pubkey_tuple[1]
        if input_script_type[0:7] == "witness":
            script_pubkey = scripts.Script.parse_hex(script_pubkey_tuple[0])
            script_pubkey_hr = script_pubkey.view()
            if script_pubkey_hr[0:4] != "OP_0" and script_pubkey_hr[0:4] != "OP_1":
                # if there is input spending segwit version > 1
                return False
            else:
                pass
        input_types.append(input_script_type)

    part_allowed_types = ["witness_v1_taproot", "witness_v0_keyhash", "pubkeyhash"]
    if check_cross_set(part_allowed_types, input_types) is True:
        # if there is at least one easy checked allowed script type in inputs
        return True
    else:
        # check if there is P2SH_P2WPKH input
        for n in range(0, len(input_script_pub_keys)):
            if input_script_pub_keys[n][1] == "pubkeyhash":
                input_being_check = transaction_vin[n]
                input_scriptsig = scripts.Script.parse_hex(input_being_check['scriptSig']['hex'])
                input_witness = input_being_check['txinwitness']
                # P2SH_P2WPKH characteristic: contain 2 stack in scriptsig and 2 stack
                if len(input_scriptsig.serialize_list()) == 2 and len(input_witness) == 2:
                    return True
                else:
                    pass
            else:
                continue
        # if not
        return False


def extract_input_hash_and_sender_key(transaction_vin: list, their_script_pub_keys: list):
    # for each eligable input, extract its pubkey, then sum them up
    # at the same time, fine the smallest outpiont
    # finally, return the summed pubkey, which is A in BIP352, and the smallest outpoint,
    # to procduce 'input_hash' in BIP352
    outpoints = []
    pubkeys = []
    for n in range(0, len(their_script_pub_keys)):
        tx_input = transaction_vin[n]
        script_pubkey_and_type = their_script_pub_keys[n]

        the_outpoint = get_bip352_outpoint(tx_input['txid'], tx_input['vout'])
        outpoints.append(the_outpoint)

        if script_pubkey_and_type[1] == "witness_v1_taproot":
            x_only_pubkey = extract_pubkey_for_taproot_input(tx_input, script_pubkey_and_type[0])
            if x_only_pubkey is not False:
                from utilities_keys import x_only_pubkey_to_point
                the_point = x_only_pubkey_to_point(x_only_pubkey)
                pubkeys.append(the_point)
        elif script_pubkey_and_type[1] == "witness_v0_keyhash":
            compressed_pubkey = tx_input['txinwitness'][1]
            from bitcoinlib import keys
            the_pubkey = keys.Key(compressed_pubkey)
            the_point = the_pubkey.public_point()
            pubkeys.append(the_point)
        elif script_pubkey_and_type[1] == "scripthash":
            from bitcoinlib import scripts
            input_scriptsig = scripts.Script.parse_hex(tx_input['scriptSig']['hex'])
            input_witness = tx_input['txinwitness']
            if len(input_scriptsig.serialize_list()) == 2 and len(input_witness) == 2:
                compressed_pubkey = input_witness[1]
                from bitcoinlib import keys
                the_pubkey = keys.Key(compressed_pubkey)
                the_point = the_pubkey.public_point()
                pubkeys.append(the_point)
            else:
                pass
        elif script_pubkey_and_type[1] == "pubkeyhash":
            from bitcoinlib import scripts
            input_scriptsig = scripts.Script.parse_hex(tx_input['scriptSig']['hex'])
            scriptsig_list = input_scriptsig.serialize_list()
            # check if it is a compressed pubkey
            if len(scriptsig_list[-1]) == 33:
                the_pubkey = scriptsig_list[-1]
                from bitcoinlib import keys
                the_pubkey = keys.Key(the_pubkey)
                the_point = the_pubkey.public_point()
                pubkeys.append(the_point)
            else:
                pass
        else:
            pass

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
    print("Downloading and dealing the block in height {} ...".format(str(block_height)))
    content = ['{}'.format(block_hash)]
    block = rpc.getblock(block_hash, True)
    tx_list = block['tx'][1:]
    for entry in tx_list:
        tx = rpc.getrawtransaction(entry, True, block_hash)
        input_script_pub_keys = []
        # For every input, get its script pubkey to check eligibility
        for coin_input in tx['vin']:
            input_script_pub_keys.append(get_prevout_script_pubkey_and_type(coin_input['txid'],
                                                                            coin_input['vout'], rpc))
        if eligible_transactions_check_by(tx['vout'], input_script_pub_keys, tx['vin']) is True:
            # extract reusable info: input hash and sender key
            input_hash, sender_key = extract_input_hash_and_sender_key(tx['vin'], input_script_pub_keys)
            content.append('{},{},{}'.format(entry, input_hash.hex(), sender_key))
            print(entry)
        else:
            pass

    print("Done.")
    return content


def read_time_chain(network_store) -> list:
    from os import path
    with open(path.join(network_store, 'time_chain'), 'r') as f:
        time_chain_str = f.read()
    time_chain_str_list = time_chain_str.split("\n")
    
    return time_chain_str_list


def prase_time_signal(a_time_signal_entry: str) -> list:
    time_signal = a_time_signal_entry.split(",")
    height_str = time_signal.pop(0)
    time_signal.insert(0, int(height_str))
    return time_signal


def write_time_chain(network_store, time_chain: list):
    from os import path
    with open(path.join(network_store, 'time_chain'), 'w') as f:
        f.write('\n'.join(time_chain))


def time_chain_complete(time_chain: list, start_height: int, end_height: int, rpc):
    # end_height block would not be included
    for n in range(start_height, end_height):
        print("Downloading header for the block in height {}".format(str(n)))
        block_hash = rpc.getblockhash(n)
        block_time_stamp = rpc.getblockheader(block_hash)['time']
        time_chain.append('{},{},{}'.format(n, block_hash, block_time_stamp))

    return time_chain


def initial_time_chain(rpc, network_store):
    zero_time_chain = []
    # Get the newest ten blocks, except the newest one
    best_block_height = rpc.getblockcount()
    zero_time_chain = time_chain_complete(zero_time_chain, best_block_height - 10, best_block_height, rpc)

    write_time_chain(network_store, zero_time_chain)

    return zero_time_chain


def update_time_chain(rpc, network_store, mode=0):
    # Mainly for dealing with time chain reorganization
    # Read the current time chain
    current_time_chain = read_time_chain(network_store)

    # Then, we need to revert re-organized time chain
    while True:
        a_time_signal = prase_time_signal(current_time_chain[-1])
        height = a_time_signal[0]
        signal_hash = a_time_signal[1]
        node_block_hash = rpc.getblockhash(height)
        if node_block_hash != signal_hash:
            current_time_chain.pop()
        else:
            break

    # Then, sync the time chain with our node
    highest = rpc.getblockcount()
    current_time_signal = prase_time_signal(current_time_chain[-1])
    current_height = current_time_signal[0]
    current_time_chain = time_chain_complete(current_time_chain, current_height, highest+1, rpc)
    
    if mode == 0:
        write_time_chain(network_store, current_time_chain)
    elif mode == 1:
        # remember manually write time_chian_file when using mode 1
        return current_time_chain


def verification_status(network_store, mode, writable_vefi_status):
    # Operations about a file named 'verification_status'
    # mode 0: check if the file exists, if not, create one
    # then, return the content
    # mode 1: write the input into the file
    from os import path
    import json
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
    time_chain = update_time_chain(rpc, network_store, 1)
    veri_status = verification_status(network_store, 0, {})

    print("Start to download and verify blocks...")
    from os import path
    for entry in time_chain:
        time_signal = prase_time_signal(entry)
        height_str = str(time_signal[0])
        varification_count = veri_status.get(height_str)
        
        if varification_count == 2:
            continue
        elif varification_count is None:
            # Typecaliy, it means we never get block for this height
            # However, we need to consider the situation that the program is shutting down before write vari_status
            # And there is a monitor mode, which will download blocks without touching time_chain file
            # If the file is not exist, download it and skip followed verification
            if not path.exists(path.join(network_store, height_str)):
                block_and_eligable_tx = deal_with_a_block(time_signal[0], time_signal[1], rpc)
                with open(path.join(network_store, height_str), 'w') as f:
                    f.write('\n'.join(block_and_eligable_tx))
                veri_status[height_str] = 0
                continue
            # If the file is exist, add verification status, then check if the block is reorganized 
            else:
                veri_status[height_str] = 0
                pass
        
        # check historically stored block is reorganized or not
        with open(path.join(network_store, height_str), 'r') as f:
            block_info = f.readline()
            block_hash = block_info[:-1]
        if time_signal[1] == block_hash:
            veri_status[height_str] += 1
        else:
            # means historically stored block is reorganized
            # overwrite new block to the file
            block_and_eligable_tx = deal_with_a_block(time_signal[0], time_signal[1], rpc)
            with open(path.join(network_store, height_str), 'w') as f:
                f.write('\n'.join(block_and_eligable_tx))
            veri_status[height_str] = 0

    # write updated time_chain and verification_status to file
    write_time_chain(network_store, time_chain)
    verification_status(network_store, 1, veri_status)
    print("Update blocks to best known.")


def monitor_mode(network_store, rpc):
    # A mode can run forever, only download blocks without touching time_chain file
    # Run downlaod_and_verify_blocks at first
    download_and_verify_blocks(network_store, rpc)
    
    current_time_chain = read_time_chain(network_store)
    from time import sleep
    from os import path
    while True:
        # check current tip in the best chain
        current_tip = prase_time_signal(current_time_chain[-1])
        current_height = current_tip[0]
        node_block_hash = rpc.getblockhash(current_height)
        if current_tip[1] == node_block_hash:
            best_block_height = rpc.getblockcount()
            if current_height < best_block_height:
                current_time_chain = time_chain_complete(current_time_chain, current_height, best_block_height+1, rpc)
                for n in range(current_height, best_block_height+1):
                    block_hash = rpc.getblockhash(n)
                    block_and_eligable_tx = deal_with_a_block(n, block_hash, rpc)
                    with open(path.join(network_store, str(n)), 'w') as f:
                        f.write('\n'.join(block_and_eligable_tx))
                sleep(60)
            else:
                sleep(60)
        else:
            # means reorganization, so we revert
            current_time_chain.pop()


def time_chain_go_deep(network_store, sp_wallet_birthday, rpc):
    time_chain = read_time_chain(network_store)

    # get history time chain if not exist
    oldest_time_signal = prase_time_signal(time_chain[0])
    oldest_height = oldest_time_signal[0]
    oldest_time_stamp = int(oldest_time_signal[2])
    while True:
        if oldest_time_stamp > sp_wallet_birthday:
            previous_blcok_height = oldest_height - 1
            previous_block_hash = rpc.getblockhash(previous_blcok_height)
            previous_block_time_stamp = rpc.getblockheader(previous_block_hash)['time']
            time_chain.insert(0, "{},{},{}".format(previous_blcok_height,
                                                   previous_block_hash, previous_block_time_stamp))
            oldest_height = previous_blcok_height
            oldest_time_stamp = previous_block_time_stamp
        else:
            break
    write_time_chain(network_store, time_chain)


def read_eligible_txs_from(network_store, block_height):
    from os import path
    with open(path.join(network_store, block_height), "r") as f:
        content = f.read()
        content_lines = content.split("\n")

    # block_hash = content_lines[0]
    eligible_txs = []
    for line in content_lines[1:]:
        line_chip = line.split(",")
        tx_info = []
        # tx_id
        tx_info.append(line_chip[0])
        # tx_input_hash
        tx_info.append(line_chip[1])
        # tx_sender_(pub)key
        tx_info.append((line_chip[2][1:], line_chip[3][:-1]))
        eligible_txs.append(tx_info)

    return eligible_txs
