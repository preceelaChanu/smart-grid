# Basic Encryption-Decryption Cycle with CKKS scheme
# 
from seal import *
import os

def get_context():
    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 60]))
    return SEALContext(parms)

def load_keys(context, input_dir):
    pk = PublicKey()
    pk.load(context, os.path.join(input_dir, "public.key"))
    sk = SecretKey()
    sk.load(context, os.path.join(input_dir, "secret.key"))
    return pk, sk

if __name__ == "__main__":
    context = get_context()
    key_dir = "/workspaces/smart-grid/keys"  # adjust path as needed
    public_key, secret_key = load_keys(context, key_dir)

    # Setup for encryption/decryption
    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    encoder = CKKSEncoder(context)

    # Example vector
    data = [3.14, 2.71, 1.41]
    scale = pow(2.0, 40)

    # Encode
    plain = encoder.encode(data, scale)

    # Encrypt
    encrypted = encryptor.encrypt(plain)

    # Decrypt
    decrypted_plain = decryptor.decrypt(encrypted)

    # Decode
    result = encoder.decode(decrypted_plain)

    # Output
    print("Input data:       ", data)
    print("Decrypted result: ", [round(x, 5) for x in result])
