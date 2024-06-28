def main():
    priv_key1 = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
    priv_key2 = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"

    redeem_script = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"

    txid_to_spend = "0000000000000000000000000000000000000000000000000000000000000000"
    idx_to_spend = 0

    sequence = "ffffffff"
    output_val_sats = int(0.001*(10**8))

    receiver_address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"

    locktime = 0

if __name__ == "__main__":
    main()



"""
References:
- bitcoin-tx-tutorial: https://github.com/chaincodelabs/bitcoin-tx-tutorial
"""