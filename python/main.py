"""
Goal:
We have been given an input locked with a P2SH-P2WSH script and we need to spend it.
Since we are using this script , the txn ought to be a segwit txn, so there should be a marker and a flag.

Approach:
(Ignoring any miner fee for now, so assuming input has 0.001 BTC )
1. create an unsigned txn with
   - version
   - marker
   - flag
   - vin
      - input count
      - for each input
        - txin
        - voutPrev
        - scriptSig (empty right now)
   - vout
       - output count
       - output amt(0.001)
       - script pubkey size
       - script pubkey(for P2SH in this case)
   - locktime
   2. Sign It
       Sign the following using the two keys and create 2 signatures
       - version
       - hashPrevOuts: hash256 of concatenated txid+vout
       - hashSeq: concatenate seq and hash256
       - txid+vout
       - scriptcode : cmpt size of witness script + witness script
       - amount 
       - seq
       - hashOutputs: hash256 of concatenated outputs
       - locktime
       - sighash
    3. fill script-sig : op0 + 32bytepush + sha256(witness_script) #check
    4. Create witness: 
       - number of stack items
       - for checkmultisig bug
       - pushbytes of sig 1
       - sig 1
       - pushbytes of sig 2
       - sig 2
       - redeem script
"""

import ecdsa
import hashlib

def main():
    privkey1 = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
    privkey2 = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"

    redeem_script = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"

    txid_to_spend = "0000000000000000000000000000000000000000000000000000000000000000"
    idx_to_spend = 0

    sequence = "ffffffff"


    locktime = 0

    # convert privkey to pubkey
    def priv_to_pub(privkey:bytes)->bytes:
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1) # privkey should be in bytes
        ver_key = sk.verifying_key
        uncompressed_pubkey = ver_key.to_string().hex()

        x_cor = bytes.fromhex(uncompressed_pubkey)[:32]
        y_cor = bytes.fromhex(uncompressed_pubkey)[32:]


        if int.from_bytes(y_cor,byteorder="big",signed=True)%2==0 :
            compressed_pubkey = bytes.fromhex("02") + x_cor
        else:
            compressed_pubkey = bytes.fromhex("03") + x_cor
        
        return compressed_pubkey
    pubkey1 = priv_to_pub(bytes.fromhex(privkey1))
    pubkey2 = priv_to_pub(bytes.fromhex(privkey2))

    # create redeem script
    redeem_script = bytes.fromhex(
        "52" + 
        "21" +
        pubkey2.hex() +
        "21" +
        pubkey1.hex() +
        "52" +
        "ae"
    )

    # check if it matches the given one
    print(redeem_script.hex()=="5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae")

    # calculate script pubkey
    def script_to_spk(redeem_script:bytes)->bytes:
        digest = hashlib.sha256(redeem_script).digest()
        spk = bytes.fromhex("0020") + digest
        return spk
    
    spk = script_to_spk(redeem_script)

    # version marker and flag
    version = bytes.fromhex("02000000")
    marker = bytes.fromhex("00")
    flag = bytes.fromhex("01")

    # to calculate compact size
    def cmptSz(data:bytes)->bytes:
        val = int.from_bytes(data)
        if (val<=252):
            return val.to_bytes(1,"little",signed=False)
        elif val>252 and val<=65535:
            return bytes.fromhex("fd") + val.to_bytes(2,"little",signed=False)
        elif val>65535 and val<=4294967295:
            return bytes.fromhex("fe") + val.to_bytes(4,"little",signed=False)
        elif val>4294967295 and val<=18446744073709551615:
            return bytes.fromhex("ff") + val.to_bytes(8,"little",signed=False)

    # inputs
    input_cnt = bytes.fromhex("01")
    txid_to_spend = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    idx_to_spend = bytes.fromhex("00000000")
    script_sig = bytes.fromhex("")
    sequence = bytes.fromhex("ffffffff")

    inputs = (
        txid_to_spend +
        idx_to_spend +
        cmptSz(script_sig) +
        script_sig +
        sequence
    )

    #decode receiver address to create spk
    receiver_address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF" # prefix => 3 so P2SH
    receiver_address = base58.b58decode("325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF")
    decoded = receiver_address[:-4]
    checksum = receiver_address[-4:]
    decoded_hash = hashlib.sha256(decoded).digest()
    # print(hashlib.sha256(decoded_hash).digest()[:4]==checksum)
    output_script_hash = decoded[1:]
    output_spk = bytes.fromhex("a9") + bytes.fromhex("14") + output_script_hash + bytes.fromhex("87") 


    # outputs
    output_ct = bytes.fromhex("01")
    output_amt_sats = int(0.01*(10**8)).to_bytes(8,byteorder="little",signed=True)

    outputs = (
        output_amt_sats + 
        cmptSz(output_spk) +
        output_spk
    )

    unsigned_tx = (
        version + 
        marker + 
        flag + 
        input_cnt + 
        inputs + 
        output_ct +
        outputs +
        locktime
    )


if __name__ == "__main__":
    main()



"""
References:
- bitcoin-tx-tutorial: https://github.com/chaincodelabs/bitcoin-tx-tutorial
- learmeabitcoin : https://learnmeabitcoin.com/
- reference implementation : https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
- opcodes : https://en.bitcoin.it/wiki/Script
- ecdsa : https://github.com/tlsfuzzer/python-ecdsa
- p2sh-p2wsh format: Programming Bitcoin by Jimmy Song(Ch -13)
- cmptSz : https://learnmeabitcoin.com/
- address prefixes: https://en.bitcoin.it/wiki/List_of_address_prefixes
- BIP141 : https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- BIP143 : https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- signing P2SH-P2WSH scripts : https://bitcoincore.org/en/segwit_wallet_dev/ and
                               https://github.com/libbitcoin/libbitcoin-system/wiki/Examples-from-Pay-to-Witness-Transactions
- what is inside the script-sig exactly : https://www.reddit.com/r/Bitcoin/comments/jmiko9/a_breakdown_of_bitcoin_standard_script_types/
"""