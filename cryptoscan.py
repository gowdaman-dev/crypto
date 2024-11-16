import random
import requests
from ecdsa import SigningKey, SECP256k1
import hashlib  # Use hashlib for Keccak-256

def generate_private_key():
    """Generate a random 256-bit private key."""
    private_key = hex(random.randint(1, 2**256 - 1))[2:].zfill(64)
    print(f"Generated Private Key: {private_key}")
    return private_key

def private_key_to_public_key(private_key):
    """Derive the public key from the private key using secp256k1 curve."""
    private_key_bytes = bytes.fromhex(private_key)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()  # Uncompressed public key
    return public_key.hex()

def public_key_to_address(public_key):
    """Derive Ethereum wallet address from public key."""
    public_key_bytes = bytes.fromhex(public_key[2:])  # Drop the "04" prefix for uncompressed key
    keccak_hash = hashlib.new('sha3_256')  # Use hashlib's Keccak-256
    keccak_hash.update(public_key_bytes)
    address = '0x' + keccak_hash.hexdigest()[-40:]  # Take last 20 bytes (40 hex characters)
    print(f"Derived Wallet Address: {address}")
    return address

def check_balance(address):
    """Check the balance of the derived wallet address using Etherscan API."""
    api_key = "QV4FV3AQ4XGWV2RKJ44XSAZCWDCP7KPBNN"  # Replace with your Etherscan API key
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses
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

if __name__ == "__main__":
    print("Starting Random Wallet Generator...")

    while True:
        try:
            private_key = generate_private_key()
            public_key = private_key_to_public_key(private_key)
            wallet_address = public_key_to_address(public_key)
            balance = check_balance(wallet_address)

            if balance is None:
                print("Could not determine wallet balance due to an error. Continuing...")
            elif balance == 0:
                print("No assets found in the wallet. Generating a new wallet...")
            else:
                print(f"Assets found: {balance} ETH")
                print(f"Private Key: {private_key}")
                print(f"Wallet Address: {wallet_address}")
                break  # Exit the loop if a wallet with balance is found
        except Exception as e:
            print(f"An unexpected error occurred: {e}. Continuing...")
