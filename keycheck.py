#!/usr/bin/env python3
"""
Bitcoin Private Key Combiner for GSMG.IO 5 BTC Puzzle
Tries multiple methods to combine two private keys and generate addresses
"""

import hashlib
import base58
import binascii

# secp256k1 parameters
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def private_key_to_wif(private_key_hex, compressed=True, testnet=False):
    """Convert private key hex to WIF format"""
    # Add version byte (0x80 for mainnet, 0xef for testnet)
    version = 0xef if testnet else 0x80
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Add version byte
    extended_key = version.to_bytes(1, 'big') + private_key_bytes
    
    # Add compression flag if compressed
    if compressed:
        extended_key += b'\x01'
    
    # Double SHA256
    hash1 = hashlib.sha256(extended_key).digest()
    hash2 = hashlib.sha256(hash1).digest()
    
    # Add first 4 bytes as checksum
    checksum = hash2[:4]
    final_key = extended_key + checksum
    
    # Base58 encode
    wif = base58.b58encode(final_key).decode('utf-8')
    return wif

def private_key_to_address(private_key_hex, compressed=True, testnet=False):
    """Convert private key to Bitcoin address"""
    import ecdsa
    from ecdsa import SECP256k1
    
    # Generate private key object
    private_key_int = int(private_key_hex, 16)
    signing_key = ecdsa.SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    
    # Get public key
    verifying_key = signing_key.get_verifying_key()
    public_key_bytes = verifying_key.to_string()
    
    # Add compression prefix
    if compressed:
        x = int.from_bytes(public_key_bytes[:32], 'big')
        y = int.from_bytes(public_key_bytes[32:], 'big')
        if y % 2 == 0:
            public_key_compressed = b'\x02' + public_key_bytes[:32]
        else:
            public_key_compressed = b'\x03' + public_key_bytes[:32]
        public_key_final = public_key_compressed
    else:
        public_key_final = b'\x04' + public_key_bytes
    
    # Hash public key (SHA256 then RIPEMD160)
    sha256_hash = hashlib.sha256(public_key_final).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    
    # Add version byte (0x00 for mainnet P2PKH)
    version = 0x6f if testnet else 0x00
    versioned_hash = version.to_bytes(1, 'big') + public_key_hash
    
    # Double SHA256 for checksum
    hash1 = hashlib.sha256(versioned_hash).digest()
    hash2 = hashlib.sha256(hash1).digest()
    checksum = hash2[:4]
    
    # Final address
    final_address = versioned_hash + checksum
    address = base58.b58encode(final_address).decode('utf-8')
    
    return address

def try_key_combinations():
    """Try different methods to combine the two private keys"""
    
    # Original keys from FINAL_PAYLOAD_KEYS.txt
    key1_hex = "d199916cf86003a78df106056cc1c3fe66986909a408e8b8e2eafebde96f6265"
    key2_hex = "b10bc764fc97d2ddaea075183026db779e0845c20cc8120d5841d50ce9c9bcce"
    
    print("=== GSMG.IO Bitcoin Key Combiner ===")
    print(f"Key1: {key1_hex}")
    print(f"Key2: {key2_hex}")
    print()
    
    results = []
    
    # Method 1: Addition (mod secp256k1 order)
    print("Method 1: Addition (mod secp256k1 order)")
    key1_int = int(key1_hex, 16)
    key2_int = int(key2_hex, 16)
    combined_add = (key1_int + key2_int) % SECP256K1_ORDER
    combined_add_hex = hex(combined_add)[2:].zfill(64)
    print(f"Combined: {combined_add_hex}")
    results.append(("Addition", combined_add_hex))
    
    # Method 2: XOR
    print("\nMethod 2: XOR")
    combined_xor = key1_int ^ key2_int
    combined_xor_hex = hex(combined_xor)[2:].zfill(64)
    print(f"Combined: {combined_xor_hex}")
    results.append(("XOR", combined_xor_hex))
    
    # Method 3: Subtraction (mod secp256k1 order)
    print("\nMethod 3: Subtraction (key1 - key2)")
    combined_sub1 = (key1_int - key2_int) % SECP256K1_ORDER
    combined_sub1_hex = hex(combined_sub1)[2:].zfill(64)
    print(f"Combined: {combined_sub1_hex}")
    results.append(("Subtraction_1", combined_sub1_hex))
    
    print("\nMethod 4: Subtraction (key2 - key1)")
    combined_sub2 = (key2_int - key1_int) % SECP256K1_ORDER
    combined_sub2_hex = hex(combined_sub2)[2:].zfill(64)
    print(f"Combined: {combined_sub2_hex}")
    results.append(("Subtraction_2", combined_sub2_hex))
    
    # Method 5: Concatenation + SHA256
    print("\nMethod 5: Concatenation + SHA256")
    concat = key1_hex + key2_hex
    concat_bytes = bytes.fromhex(concat)
    combined_sha = hashlib.sha256(concat_bytes).hexdigest()
    print(f"Combined: {combined_sha}")
    results.append(("Concatenation_SHA256", combined_sha))
    
    # Method 6: Half and Better Half combinations
    print("\nMethod 6: Half combinations")
    # First half of key1 + second half of key2
    half1_key1 = key1_hex[:32]  # First 32 chars (16 bytes)
    half2_key2 = key2_hex[32:]  # Last 32 chars (16 bytes)
    combined_half1 = half1_key1 + half2_key2
    print(f"Key1_first_half + Key2_second_half: {combined_half1}")
    results.append(("Half1+Half2", combined_half1))
    
    # First half of key2 + second half of key1
    half1_key2 = key2_hex[:32]
    half2_key1 = key1_hex[32:]
    combined_half2 = half1_key2 + half2_key1
    print(f"Key2_first_half + Key1_second_half: {combined_half2}")
    results.append(("Half2+Half1", combined_half2))
    
    # Method 7: Multiplication (mod secp256k1 order)
    print("\nMethod 7: Multiplication")
    combined_mult = (key1_int * key2_int) % SECP256K1_ORDER
    combined_mult_hex = hex(combined_mult)[2:].zfill(64)
    print(f"Combined: {combined_mult_hex}")
    results.append(("Multiplication", combined_mult_hex))
    
    return results

def generate_addresses_for_keys(results):
    """Generate addresses for all combined keys"""
    print("\n" + "="*80)
    print("GENERATING ADDRESSES FOR ALL COMBINATIONS")
    print("="*80)
    
    try:
        import ecdsa
    except ImportError:
        print("ERROR: ecdsa library not found. Install with: pip install ecdsa")
        print("Showing WIF formats only...")
        print()
        
        for method, key_hex in results:
            print(f"\n--- {method} ---")
            print(f"Private Key: {key_hex}")
            try:
                wif_compressed = private_key_to_wif(key_hex, compressed=True)
                wif_uncompressed = private_key_to_wif(key_hex, compressed=False)
                print(f"WIF Compressed:   {wif_compressed}")
                print(f"WIF Uncompressed: {wif_uncompressed}")
            except Exception as e:
                print(f"Error generating WIF: {e}")
        return
    
    for method, key_hex in results:
        print(f"\n--- {method} ---")
        print(f"Private Key: {key_hex}")
        
        try:
            # Generate WIF formats
            wif_compressed = private_key_to_wif(key_hex, compressed=True)
            wif_uncompressed = private_key_to_wif(key_hex, compressed=False)
            
            # Generate addresses
            addr_compressed = private_key_to_address(key_hex, compressed=True)
            addr_uncompressed = private_key_to_address(key_hex, compressed=False)
            
            print(f"WIF Compressed:   {wif_compressed}")
            print(f"WIF Uncompressed: {wif_uncompressed}")
            print(f"Address Compressed:   {addr_compressed}")
            print(f"Address Uncompressed: {addr_uncompressed}")
            
            # Check if any address starts with "1gsm"
            if addr_compressed.startswith("1gsm") or addr_uncompressed.startswith("1gsm"):
                print(f"*** POTENTIAL MATCH FOUND! Method: {method} ***")
                
        except Exception as e:
            print(f"Error processing {method}: {e}")

def main():
    print("GSMG.IO 5 BTC Puzzle - Private Key Combiner")
    print("Attempting to combine two private keys using various methods...")
    print()
    
    # Try different combination methods
    results = try_key_combinations()
    
    # Generate addresses for all combinations
    generate_addresses_for_keys(results)
    
    print("\n" + "="*80)
    print("SUMMARY:")
    print("Look for addresses starting with '1gsm' in the output above.")
    print("If no matches found, the puzzle may require additional steps.")
    print("="*80)

if __name__ == "__main__":
    main()
