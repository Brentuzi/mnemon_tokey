import hashlib, hmac, struct
from ecdsa.curves import Ed25519

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_SEED_ED25519 = b'ed25519 seed'
APTOS_DERIVATION_PATH = "m/44'/637'/0'/0'/0'"


class PublicKey25519:
    def __init__(self, private_key):
        self.private_key = private_key

    def __bytes__(self):
        sk = Ed25519.SigningKey(self.private_key)
        return b'\x00' + sk.get_verifying_key().to_bytes()


class PublicKeyUtils:

    def __init__(self, words, str_derivation_path=APTOS_DERIVATION_PATH, curve=Ed25519, modifier=BIP32_SEED_ED25519):
        self.privdev = BIP32_PRIVDEV
        self.curve = curve
        self.str_derivation_path = str_derivation_path
        self.modifier = modifier

        self.private_key = self.mnemonic_to_private_key(words)
        self.public_key = PublicKey25519(self.private_key)

    def derive_bip32childkey(self, parent_key, parent_chain_code, i):
        assert len(parent_key) == 32
        assert len(parent_chain_code) == 32
        k = parent_chain_code
        if (i & self.privdev) != 0:
            key = b'\x00' + parent_key
        else:
            key = bytes(PublicKey25519(parent_key))

        d = key + struct.pack('>L', i)

        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]

        return key, chain_code

    @staticmethod
    def mnemonic_to_bip39seed(mnemonic, passphrase):
        mnemonic = bytes(mnemonic, 'utf8')
        salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
        return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)

    def mnemonic_to_private_key(self, mnemonic, passphrase=""):
        derivation_path = self.parse_derivation_path()
        bip39seed = self.mnemonic_to_bip39seed(mnemonic, passphrase)
        master_private_key, master_chain_code = self.bip39seed_to_bip32masternode(bip39seed)
        private_key, chain_code = master_private_key, master_chain_code
        for i in derivation_path:
            private_key, chain_code = self.derive_bip32childkey(private_key, chain_code, i)
        return private_key

    def bip39seed_to_bip32masternode(self, seed):
        k = seed
        h = hmac.new(self.modifier, seed, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        return key, chain_code

    def parse_derivation_path(self):
        path = []
        if self.str_derivation_path[0:2] != 'm/':
            raise ValueError("Can't recognize derivation path. It should look like \"m/44'/chaincode/change'/index\".")
        for i in self.str_derivation_path.lstrip('m/').split('/'):
            if "'" in i:
                path.append(self.privdev + int(i[:-1]))
            else:
                path.append(int(i))

        return path

def main():
    with open('input.txt', 'r') as infile:
        mnemonics = infile.read().strip().splitlines()

    private_keys = []

    for mnemonic in mnemonics:
        try:
            utils = PublicKeyUtils(mnemonic)
            private_key = "0x" + utils.private_key.hex()
            private_keys.append(private_key)
        except Exception as e:
            print(f"Error processing mnemonic {mnemonic}: {e}")

    with open('output.txt', 'w') as outfile:
        for key in private_keys:
            outfile.write(key + '\n')

    print(f"Processed {len(mnemonics)} mnemonics. Keys saved to 'output.txt'.")




if __name__ == '__main__':
    main()
