def list_folders_in(parent_path) -> list:
    from os import path, makedirs, listdir
    if not path.exists(parent_path):
        makedirs(parent_path)
    all_items = listdir(parent_path)
    folders = [item for item in all_items if path.isdir(path.join(parent_path, item))]
    return folders


def ui_choicer(options_list: list) -> str:
    display = "请在以下选项中选择：\n"
    up_cap = len(options_list)
    for n in range(0, up_cap):
        display += '{}. {}\n'.format(str(n), options_list[n])
    print(display)

    while True:
        choice = input("请输入选项前面的序号：")
        try:
            choice = int(choice)
        except:
            print("您输入的不是整数。")
            continue

        if choice >= up_cap:
            print("您未输入有效的序号。")
        else:
            return options_list[choice]


def any_confirm(document: str) -> bool:
    keyboard_input = input(document + "输入小写字母 “q” 将撤销选择。输入其它任意字符按回车都将表示确认：")
    if keyboard_input == "q":
        return False
    else:
        return True


def get_payment_intention():
    destination_address = input("请输入接收方的地址：")

    from decimal import Decimal
    while True:
        payment_amount = input("请输入支付金额，以 BTC 为单位：")
        try:
            Decimal(payment_amount)
            break
        except:
            print("输入有误。请重新输入。\n")

    while True:
        confirm_target = input("您想在多少个区块内确认？请输入数字：")
        try:
            int(confirm_target)
            break
        except:
            print("输入有误。请重新输入。\n")

    return (destination_address, payment_amount, confirm_target)


def select_coins_in(sp_allowed_utxos, payment_amount_need, confirm_target, wallet_rpc):
    # Let the user manually select coins for sp payment
    from decimal import Decimal
    from utilities_wallet import solve_output_type_by
    from utilities_wallet import size_in_vbytes_table_of
    amount_target = Decimal(payment_amount_need)
    estimated_fee_rate = wallet_rpc.estimatesmartfee(confirm_target, "CONSERVATIVE")

    print("本次静默支付的目标金额是 {} BTC。你需要从可用的资金中选出总价值超过该金额（且足以支付手续费）的部分。".format(
        payment_amount_need))
    selected_amount = Decimal(0)
    selected_coins = []
    # Assume the user will spend at least one segwit input, and produce one taproot output for sp
    # Here we don't need to be very precise
    tx_size_in_vbytes = Decimal(10.5) + Decimal(43)
    while True:
        print("\n当前已选中的资金的总价值为 {} BTC。请在下列选项中继续选择你要使用的资金：".format(str(selected_amount)))
        up_cap = len(sp_allowed_utxos)
        for n in range(0, up_cap):
            script_pubkey_type = solve_output_type_by(sp_allowed_utxos[n]["address"])
            print("{}. 价值： {} BTC，地址类型：{}，资金存放时间：{} 个区块".format(str(n),
                                                                               str(sp_allowed_utxos[n]["amount"]),
                                                                               script_pubkey_type, str(
                    sp_allowed_utxos[n]["confirmations"])))
        while True:
            selection = input("请通过输入选项前面的序号来选择资金。务必仅输入**一个**序号：")
            try:
                int(selection)
            except:
                print("您输入的不是数字，请再次输入。")

            if int(selection) >= up_cap:
                print("您所输入的序号超出了范围。请在可选项中选择。")
            else:
                break

        selection = int(selection)
        selected_coin = sp_allowed_utxos.pop(selection)
        selected_amount += selected_coin["amount"]
        tx_size_in_vbytes += size_in_vbytes_table_of(selected_coin["address"])
        selected_coins.append(selected_coin)
        if selected_amount >= amount_target + estimated_fee_rate * tx_size_in_vbytes:
            return selected_coins
        else:
            if len(sp_allowed_utxos) == 0:
                return False
            else:
                pass


def rg_wallet_mode(node_rpc, node_info):
    import utilities_wallet
    from os import path
    rg_wallet_interface = ["了解余额", "获取收款地址", "发送普通支付", "发送静默支付", "退出本钱包"]
    rg_wallet_parent_path = path.join('./wallets/rg_wallets', node_info["network"])

    wallet_list = list_folders_in(rg_wallet_parent_path) + ["创建新钱包", "返回上一级"]
    selected_wallet = ui_choicer(wallet_list)
    if selected_wallet == "返回上一级":
        return
    elif selected_wallet == "创建新钱包":
        wallet_name = input("请输入钱包的名称，按回车结束：\n")
        import getpass
        wallet_password = getpass.getpass(
            "请输入 锁定/解锁 该钱包的口令。输入任何字符、任何长度都不会显示出来。按回车结束：")
        abslute_wallet_path = path.abspath(path.join(rg_wallet_parent_path, wallet_name))
        utilities_wallet.create_a_rg_wallet(abslute_wallet_path, wallet_password, node_rpc)
        if path.exists(abslute_wallet_path) is True:
            print("创建成功！\n")
        else:
            print("创建失败。请检查您的输入是否有误。\n")
    else:
        abslute_wallet_path = path.abspath(path.join(rg_wallet_parent_path, selected_wallet))
        node_rpc.loadwallet(abslute_wallet_path)
        print("正在为您打开名为 “{}” 的钱包。".format(selected_wallet))

    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
    wallet_rpc = AuthServiceProxy(
        "http://{}:{}@{}/wallet/{}".format(node_info["rpcuser"], node_info["rpcpassword"], node_info["server-port"],
                                           abslute_wallet_path))
    while True:
        select = ui_choicer(rg_wallet_interface)
        if select == "退出本钱包":
            node_rpc.unloadwallet(abslute_wallet_path)
            break
        elif select == "了解余额":
            utilities_wallet.know_a_rg_wallet_balance(wallet_rpc)
        elif select == "获取收款地址":
            print(utilities_wallet.get_a_receving_address(wallet_rpc))
        else:
            print("本钱包当前余额为：{}。".format(utilities_wallet.know_a_rg_wallet_balance(wallet_rpc)))
            import getpass
            while True:
                password = getpass.getpass(
                    "请输入解锁该钱包的口令。注意，无论输入什么，都不会在屏幕上显示出来。按回车结束：")
                performance = wallet_rpc.walletpassphrase(password, 300)
                if performance == {}:
                    print("成功解锁。该钱包将保持解锁 5 分钟。请在 5 分钟内完成交易发送，否则可能出错。")
                    break
                else:
                    print("口令错误。请尝试重新选择输入口令。\n")

            if select == "发送普通支付":
                print("您正在尝试发送常规支付。单次操作只能安排一个接收方。")
                payment_intention_tuple = get_payment_intention()
                payment_confirm_message = ("请再次确认，您正在尝试发送交易：\n目标地址：{}\n支付数额：{} BTC\n"
                                           "希望在 {} 个区块内确认\n。").format(
                    payment_intention_tuple[0], payment_intention_tuple[1], payment_intention_tuple[2])
                if any_confirm(payment_confirm_message) is False:
                    continue
                else:
                    this_tx_id = utilities_wallet.send_a_rg_payment_from_a_rg_wallet(payment_intention_tuple,
                                                                                     wallet_rpc)
                    print("如果交易发送成功，您将在下一行看到交易的 ID。否则，您将看到报错消息。"
                          "您可以安全地尝试再次发送。\n{}".format(this_tx_id))
                print("现在，本钱包会重新锁定。")
                wallet_rpc.walletlock()
            elif select == "发送静默支付":
                print("您正在尝试发送静默支付。单次操作只能安排一个接收方。")
                print("由于不可使用多签输入，您可能无法动用钱包中的全部余额。")
                usable_coins, usable_balance = utilities_wallet.collect_sp_allowed_coin_and_balance_in_a_rg_wallet_by(
                    wallet_rpc)
                print("您可以用于发送静默支付的余额是：{} BTC。".format(usable_balance))
                while True:
                    payment_intention_tuple = get_payment_intention()
                    coin_selection_result = select_coins_in(usable_coins, payment_intention_tuple[1],
                                                            payment_intention_tuple[2], wallet_rpc)
                    if coin_selection_result is False:
                        print("可用于发送静默支付的余额不足以在当前的网络费率条件下支付目标金额。请重新输入支付目标。")
                    else:
                        break
                payment_confirm_message = ("请再次确认，您正在尝试发送交易：\n目标地址：{}\n支付数额：{} BTC\n"
                                           "希望在 {} 个区块内确认\n。").format(
                    payment_intention_tuple[0], payment_intention_tuple[1], payment_intention_tuple[2])
                if any_confirm(payment_confirm_message) is False:
                    continue
                else:
                    transaction_result = utilities_wallet.send_a_sp_payment_from_a_rg_wallet(
                        coin_selection_result, payment_intention_tuple, wallet_rpc)
                    if transaction_result == "sp_address_error":
                        print("您所输入的静默支付地址是无效的。请重新开始发送交易吧。")
                    elif transaction_result == "input_privete_key_error":
                        print("这组资金不适合发起静默支付交易。请选择另一组资金吧。")
                    elif transaction_result == "t_k_error":
                        print("这组资金不适合向这个静默支付钱包主体发送交易。更换资金或支付对象都可能产生有效的交易。")
                    else:
                        print("如果交易发送成功，您将在下一行看到交易的 ID。否则，您将看到报错消息。"
                              "您可以安全地尝试再次发送。\n{}".format(transaction_result))
                print("现在，本钱包会重新锁定。")
                wallet_rpc.walletlock()


def generate_sp_address(wallet_info, wallet_path):
    label_key_number = len(wallet_info["used_labeled_key"]) - 1
    print("您已经有 {} 个带标签的花费密钥。".format(str(label_key_number)))
    print("每个花费密钥都可以编码成一个独一无二的静默支付地址。")
    available_label = [str(n) for n in range(1, label_key_number + 1)]
    print("因此，您现在可以使用的标签有：{}".format(", ".join(available_label)))
    label_choice = input("请使用数字，从上述标签中选择你要使用的标签。如果输入其它数字，将递增数字、产生新标签和相应的地址。")
    try:
        label_choice_int = int(label_choice)
        if label_choice_int > 0 and label_choice_int <= label_key_number:
            key_name = "B_{}".format(label_choice)
            spend_key_in_address = wallet_info["used_labeled_key"][key_name]
        else:
            from utilities_keys import get_a_labeled_spend_key, ser_public_key
            from bitcoinlib import keys
            from utilities_wallet import write_a_sp_wallet_info
            key_name = "B_{}".format(str(label_key_number+1))
            original_spend_pub_bytes = wallet_info["spend_pub_key"]
            original_spend_pub_key = keys.Key(import_key=original_spend_pub_bytes)
            original_spend_pub_point = original_spend_pub_key.public_point()
            spend_key_in_address = get_a_labeled_spend_key(original_spend_pub_point,
                                                           wallet_info["scan_private_key"], label_key_number+1)
            wallet_info["used_labeled_key"][key_name] = spend_key_in_address
            write_a_sp_wallet_info(wallet_path, wallet_info)
        import bech32m
        from bech32m import Encoding
        data_need_encord = int(0).to_bytes() + wallet_info["scan_pub_key"] + ser_public_key(spend_key_in_address)
        mainnet_address = bech32m.bech32_encode("sp", data_need_encord, Encoding.BECH32M)
        testnet_address = bech32m.bech32_encode("tsp", data_need_encord, Encoding.BECH32M)
        print("用于主网的静默支付地址：{}".format(mainnet_address))
        print("用于测试网的静默支付地址：{}".format(testnet_address))
    except:
        print("您输入的并非数字。请重新来过。")
        return



def sp_wallet_mode(node_rpc, network):
    import utilities_wallet
    from os import path
    sp_wallet_interface = ["扫描支付", "了解余额", "生成静默支付地址", "退出本钱包"]
    sp_wallet_parent_path = path.join('./wallets/sp_wallets', network)

    wallet_list = list_folders_in(sp_wallet_parent_path) + ["创建新钱包", "返回上一级"]
    selected_wallet = ui_choicer(wallet_list)
    if selected_wallet == "返回上一级":
        return
    elif selected_wallet == "创建新钱包":
        wallet_name = input("请输入钱包的名称，按回车结束：\n")
        import getpass
        wallet_password = getpass.getpass(
            "请输入 锁定/解锁 该钱包的口令。输入任何字符、任何长度都不会显示出来。按回车结束：")
        wallet_path = path.join(sp_wallet_parent_path, wallet_name)
        wallet_info = utilities_wallet.create_a_sp_wallet(wallet_path, wallet_password)
        if path.exists(wallet_path) is True:
            print("创建成功！\n")
        else:
            print("创建失败。请检查您的输入是否有误。\n")
    else:
        wallet_path = path.join(sp_wallet_parent_path, selected_wallet)
        print("正在为您打开名为 “{}” 的钱包。".format(selected_wallet))
        wallet_info = utilities_wallet.read_a_sp_wallet_info(wallet_path)

    while True:
        select = ui_choicer(sp_wallet_interface)
        if select == "退出本钱包":
            break
        elif select == "扫描支付":
            print("即将开始扫描区块链以了解与本钱包有关的静默支付。此过程可能花费很长时间，请耐心等待。")
            wallet_info = utilities_wallet.scan_blockchain_for_sp_wallet(wallet_info, wallet_path, network, node_rpc)
            print("已完成扫描。您可通过 “了解余额” 功能了解本钱包的余额。")
        elif select == "了解余额":
            amount = utilities_wallet.know_a_sp_wallet_balance(wallet_info)
            print("本钱包拥有 {} BTC。".format(amount))
        elif select == "获取收款地址":
            generate_sp_address(wallet_info, wallet_path)


def gudugudu():
    print("正在加载节点配置信息...")
    import utilities_scan

    node_info = utilities_scan.read_node_info()
    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
    rpc = AuthServiceProxy(
        "http://{}:{}@{}".format(node_info['rpcuser'], node_info['rpcpassword'], node_info['server-port']))

    from os import path
    from os import makedirs
    network_store = path.join('./sp-transactions-candidate', node_info['network'])
    print(network_store)
    if not path.exists(network_store):
        print("正在为新网络创建存储目录...")
        makedirs(network_store)
        utilities_scan.initial_time_chain(rpc, network_store)
        print("创建完成")
    else:
        print("正在为使用过的网络追赶时间链的进展...")
        utilities_scan.update_time_chain(rpc, network_store)
        print("追上了")

    print("\n欢迎使用 Gudugudu 钱包！\n")

    first_interface = ["静默支付钱包", "普通钱包", "同步区块模式", "退出程序"]

    while True:
        mode = ui_choicer(first_interface)
        if mode == "退出程序":
            break
        elif mode == "同步区块模式":
            go_on = any_confirm(
                "本模式是专为静默支付钱包设计的。它将获取区块并抽出其中可能的静默支付交易，直至最新区块。"
                "如果您不使用静默支付钱包，您不需要这个模式。\n")
            if go_on is False:
                continue
            else:
                utilities_scan.download_and_verify_blocks(network_store, rpc)
        elif mode == "普通钱包":
            rg_wallet_mode(rpc, node_info)
        elif mode == "静默支付钱包":
            sp_wallet_mode(rpc, node_info["network"])


if __name__ == '__main__':
    gudugudu()
