from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from ecdsa import SigningKey, SECP256k1
import hashlib
import requests
import time

def generate_mnemonic():
    """Generate a mnemonic phrase using BIP39."""
    mnemo = Mnemonic("english")
    phrase = mnemo.generate(strength=128)  # 12-word mnemonic
    print(f"Mnemonic Phrase: {phrase}")
    return phrase

def mnemonic_to_seed(phrase, passphrase=""):
    """Convert mnemonic phrase to seed."""
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(phrase, passphrase)
    print(f"Seed: {seed.hex()}")
    return seed

def derive_private_key(seed):
    """Derive private key using BIP44 path for Ethereum."""
    bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
    # Derivation path for Ethereum: m/44'/60'/0'/0/0
    derived_ctx = bip32_ctx.DerivePath("m/44'/60'/0'/0/0")
    private_key = derived_ctx.PrivateKey().Raw().ToHex()
    print(f"Derived Private Key: {private_key}")
    return bytes.fromhex(private_key)

def private_key_to_address(private_key):
    """Convert private key to Ethereum wallet address."""
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Uncompressed public key
    keccak_hash = hashlib.new('sha3_256')
    keccak_hash.update(public_key[1:])  # Exclude the 0x04 prefix
    address = '0x' + keccak_hash.hexdigest()[-40:]  # Last 20 bytes
    print(f"Wallet Address: {address}")
    return address

def check_balance(address):
    """Check Ethereum wallet balance using Etherscan API."""
    api_key = "QV4FV3AQ4XGWV2RKJ44XSAZCWDCP7KPBNN"  # Replace with your API key
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get('status') == "1":
            balance_wei = int(data.get('result', 0))
            balance_eth = balance_wei / (10**18)  # Convert Wei to Ether
            print(f"Wallet Balance: {balance_eth} ETH")
            return balance_eth
        else:
            print(f"Error fetching balance: {data.get('message')}")
            return None
    except requests.RequestException as e:
        print(f"HTTP Request failed: {e}")
        return None

if _name_ == "_main_":
    print("Starting Mnemonic Wallet Generator Loop...")
    try:
        while True:
            # Generate a wallet
            phrase = generate_mnemonic()
            seed = mnemonic_to_seed(phrase)
            private_key = derive_private_key(seed)
            address = private_key_to_address(private_key)

            # Check wallet balance
            balance = check_balance(address)

            if balance is None:
                print("Could not determine wallet balance due to an error. Retrying...")
            elif balance > 0:
                print(f"Wallet with assets found: {balance} ETH")
                print(f"Mnemonic Phrase: {phrase}")
                print(f"Private Key: {private_key.hex()}")
                print(f"Wallet Address: {address}")
                break  # Exit loop once wallet with assets is found
            else:
                print("No assets found in the wallet. Generating a new wallet...")
            
            # To avoid hitting API limits, add a delay (optional)
            time.sleep(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
