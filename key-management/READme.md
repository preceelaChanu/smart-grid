This directory contains scripts and documentation for generating, storing, and loading cryptographic keys for the CKKS homomorphic encryption scheme, using the Python bindings for Microsoft SEAL.

Contents
ckks_key_manager.py : Main script for CKKS key lifecycle management

Generated key files in keys/:

public.key (public key, for encryption)

secret.key (secret key, for decryption)

relin.key (relinearization key, for multiplication of ciphertexts)

galois.key (Galois key, for rotating encrypted vectors)

Purpose
These keys enable privacy-preserving data analytics across smart grid nodes (edge, fog, cloud) by supporting secure encryption, decryption, encrypted computation, and rotation of real-valued data.