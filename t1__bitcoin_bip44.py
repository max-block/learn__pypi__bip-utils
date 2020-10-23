from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins

mnemonic = "disorder list exit unveil ski hand subject hen clean life sponsor praise expand nature tobacco orange actress when lion begin dash luxury found convince"  # noqa
passphrase = "mega-secret"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
# Generate BIP44 chain keys: m/44'/0'/0'/0
bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)

# Generate the address pool (first 20 addresses): m/44'/0'/0'/0/i
for i in range(20):
    bip_obj_addr = bip_obj_chain.AddressIndex(i)
    address = bip_obj_addr.PublicKey().ToAddress()
    private = bip_obj_addr.PrivateKey().ToWif()

    print(f"{address} / {private}")
