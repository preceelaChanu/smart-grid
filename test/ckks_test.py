# Testing setup for CKKS scheme: Encrypt, Decrypt, and Evaluate

from seal import (
    EncryptionParameters, SEALContext, KeyGenerator, CKKSEncoder, Encryptor, Decryptor, Evaluator, scheme_type, CoeffModulus)


import math

parms = EncryptionParameters(scheme_type.ckks)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40 ,40]))

context = SEALContext(parms)

kaygen = KeyGenerator(context)
public_key = kaygen.create_public_key()
secret_key = kaygen.secret_key()

encryptor = Encryptor(context, public_key)
decryptor = Decryptor(context, secret_key)
encoder = CKKSEncoder(context)
evaluator = Evaluator(context)

scale = pow(2.0, 40)

values = [1.5, 2.0 , 3.7]

plain = encoder.encode(values, scale)
encrypted = encryptor.encrypt(plain)

encrypted_squared = evaluator.square(encrypted)

plain_result = decryptor.decrypt(encrypted_squared)

decoded_result = encoder.decode(plain_result)

print("Original input:", values)
print("Decrypted squared result:", decoded_result)