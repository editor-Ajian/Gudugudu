# Gudugudu: A Python Silent Payment extension wallet

('Gudugudu' sounds like talk in the water.)

This python library contains an extension wallet for 'Silent Payments', using `Bitcoin Core` as its backend.

该 Python 库包含一个 “静默支付” 的插件钱包,使用 `Bitcoin Core` 作为其后端。

## Silent Payments

'Silent Payments (SPs)' is a special payment method, which allows the payment receiver to use a (pair of) public key(s) as a static address without 'address reuse' problem -- every time and every sender will generate a new address based on the receiver's public key(s).

This technical is inspired by a well-known cryptographic concept, called 'Deffie-Hellman key exchange': if two parties have their own public key and private key, they can generate a shared secret key, which is only knowable by them, by multiplying the local private key with the other's public key.

To apply this concept in bitcoin payments, the sender need to use private keys in transaction inputs, combined with the receiver's public key(s), to generate scriptPubKey for the receiver's transaction output -- only the receiver can determine whether the output is sent to him/her.

The main specification and document:

- BIP 352 Silent Payments: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
- Optech topics·Silent payments: https://bitcoinops.org/en/topics/silent-payments/

“静默支付(SP)” 是一种特殊的支付方式，它允许收款人使用一个（或一对）公钥作为静态地址，同时避免了 “地址重用” 的问题 —— 每个发送者在每次支付时都会基于接收者的公钥生成一个新的地址。

这项技术的灵感来自一个著名的密码学概念，叫做 “迪菲-赫尔曼密钥交换”：如果双方各自拥有自己的公钥和私钥，他们可以通过将己方的私钥与对方的公钥相乘，来生成一个共享的秘密值（私钥），这个秘密值只有他们双方才能知道。

要在比特币支付中应用这个概念，发送者需要使用交易输入中的私钥，结合接收者的公钥，为发送给接收者的交易输出生成脚本公钥 —— 只有接收者才能确定该输出是否属于 他/她。

主要规范和文档:

- BIP 352 Silent Payments: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
- Optech topics·Silent payments: https://bitcoinops.org/en/topics/silent-payments/

## Implement Ideas

Note: `Bitcoin Core` internal support for SPs is on the way, see [this PR](https://github.com/bitcoin/bitcoin/issues/28536). This effort is obviously less qualified. 

There are bugs. Do not use it for purposes other than test and development.

注意：`Bitcoin Core` 对静默支付的支持正在实现中，见[此 PR](https://github.com/bitcoin/bitcoin/issues/28536)。本库的质量无法与之相比。

程序中还有 bug，只应用来测试和进一步开发。

The ideas behind BIP352 are straight forward:

- The receiver generates sp public keys and publish sp addresses. 
- Then, the sender, uses private keys in all inputs of the transaction, with one of sp address, to send a silent payment.
- Then, the receiver scans blockchain to receive payments.

It implies that, at first, as a receiver, we should be able to:

- Generate sp keys, sp addresses and store them
- Scan blockchain to find silent payments out

Note: For the idea of domain separation, we implements sp public keys as a dedicated pair of keys, instead of using BIP32 HD wallets.

Here, a trick is, as the sender uses all private keys, part of information got from scanning (a conceptual 'sender key' for a transaction) is reusable, no matter what is your sp public keys. It imples a concept of 'silent payment light client', which is captured by BIP352. It is also the reason we store eligable transactions and their sender key in 'sp-transaction-candidate' folder.

Finally, as a sender (wallet manager), we should be able to:

- Correctly sign silent payment outputs to send transactions
  - Send regular payments is basic requirement, as it allow us to sweep outputs to our another non-sp wallet (like a cold wallet or a HD hot wallet.)
  - However, for sending payment to others, the ability to send sp is necessary as our change address is also a sp address.
  - Multi parties contributes inputs to a silent payment is possible, however, the tools (specs and implementations) are still discussed, which is not our goals, at least now.
- Record historical transactions for accounting.

Nonetheless, a sp wallet software have to support regular receiving payments/wallets, otherwise it can't run/be tested by itself. Here, we have a round-about method: using the wallet module of `Bitcoin Core`, to reduce the complexity.

BIP352 背后的想法很简单:

- 接收者生成 sp 公钥并发布 sp 地址。
- 发送者使用交易的所有输入中的私钥，选定一个 sp 地址来发送静默支付。
- 然后，接收者扫描区块链以接收付款。

那么，作为接收者，我们应该能够：

- 生成 sp 密钥、sp 地址并存储它们
- 扫描区块链以查找静默支付

注意：出于域分隔的思想，本实现将 sp 公钥实现为专门的一对密钥，而不使用 BIP32 HD 钱包。

有趣之处在于，由于发送者使用交易的所有输入的私钥来构造接收者的收款脚本，从扫描获得的部分信息（各交易在概念上的 “发送者密钥”）是可重用的，对任何扫描静默支付的接收者都有用。这就暗示着一种 “静默支付轻客户端” 的概念，并且也已经被 BIP352 阐明。这就是本实现将符合条件的交易及其发送者密钥存储在 “sp-transaction-candidate” 文件夹中的原因。

最后，作为发送者（钱包管理者），我们应该能够：

- 正确签署静默支付输出以发送交易
    - 发送常规付款是基本要求，因为它允许我们将输出转移到我们的另一个非 sp 钱包（如冷钱包或层级确定式热钱包）中。
    - 但是，如果要向他人付款，发送 sp 的能力是必要的，因为我们的找零地址也是一个 sp 地址。
    - 多个参与者分别为静默支付贡献输入是可能的，但是，工具（规范和实现）仍在讨论中，本实现暂时不打算实现这种特性。
- 记录历史交易以进行审计。

此外，静默支付钱包也必须支持常规钱包，否则它将无法独立 测试/运行。在此，本实现采取了一种迂回的办法：调用 Bitcoin Core 的钱包模块；以降低实现的复杂性。

## Dependencies and Bitcoin node config

Software/Library dependencies:

- [python-bitcoinlib](https://github.com/petertodd/python-bitcoinlib)
- [python-bitcoinrpc](https://github.com/jgarzik/python-bitcoinrpc)
- [ecdsa](https://github.com/tlsfuzzer/python-ecdsa)

`Bitcoin Core` node config:

Must set `txindex=1` in node configure file.

必须在 `Bitcoin Core` 的配置文件中设定 `txindex=1`。

## Features

- [x] Mainnet/Testnet support
- [x] Scan blockchain for silent payment
- Silent Payments wallet
  - [x] Generate silent payment keys (spend keys and scan keys)
  - [x] Encrypted spend secret key store (BIP38)
  - [x] Generate silent payment addresses
  - [ ] Sweep a wallet to another regular wallet
  - [ ] Differentiate historical transactions with available balance
- Regular wallet
  - [x] Receive regular payments
  - [x] Send regular payments
  - [x] Send silent payments
- Transaction features
  - [] Multi receivers
  - [] Coin selection (part)
  - [] RBF