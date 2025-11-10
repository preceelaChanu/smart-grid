from seal import *
import os

def get_context():
    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 60]))
    return SEALContext(parms)

def generate_keys(context, output_dir="."):
    keygen = KeyGenerator(context)
    public_key = keygen.create_public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.create_relin_keys()
    galois_keys = keygen.create_galois_keys()
    public_key.save(os.path.join(output_dir, "public.key"))
    secret_key.save(os.path.join(output_dir, "secret.key"))
    relin_keys.save(os.path.join(output_dir, "relin.key"))
    galois_keys.save(os.path.join(output_dir, "galois.key"))
    print("All keys generated and saved.")

def load_keys(context, input_dir="."):
    pk = PublicKey()
    pk.load(context, os.path.join(input_dir, "public.key"))
    sk = SecretKey()
    sk.load(context, os.path.join(input_dir, "secret.key"))
    rk = RelinKeys()
    rk.load(context, os.path.join(input_dir, "relin.key"))
    gk = GaloisKeys()
    gk.load(context, os.path.join(input_dir, "galois.key"))
    print("All keys loaded.")
    return pk, sk, rk, gk

if __name__ == "__main__":
    context = get_context()
    generate_keys(context)
    load_keys(context)
