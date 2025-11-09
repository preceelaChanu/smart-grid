/*
 * =============================================================
 * DAY 2: "HELLO, HOMOMORPHIC ENCRYPTION!"
 * =============================================================
 * This is a minimal, complete program using Microsoft SEAL (BFV).
 * It demonstrates the full crypto-cycle:
 * 1. Set up Parameters
 * 2. Generate Keys
 * 3. Encrypt Plaintext Data
 * 4. Perform Homomorphic Computation (Addition)
 * 5. Decrypt the Result
 * 6. Verify the answer
 */

// Includes from the SEAL library

#include <chrono> // For high-resolution timing
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

/*
 * =============================================================
 * A simple high-resolution timer class
 * =============================================================
 */
class Timer {
public:
    void start() {
        start_time = chrono::high_resolution_clock::now();
    }

    void stop(const string& operation_name) {
        auto end_time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
        cout << "[Benchmark] " << operation_name << ": " 
             << duration.count() << " microseconds (" 
             << duration.count() / 1000.0 << " ms)" << endl;
    }

private:
    chrono::high_resolution_clock::time_point start_time;
};

int main()
{

    Timer timer;
    timer.start();
    // --- 1. Set up Parameters ---

    // Define the encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    

    // Set the security level.
    // 8192 is a good starting point. This is the main variable
    // you will change in your 15-day plan.
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // Set the coefficient modulus (the "space" for ciphertexts)
    // SEAL provides helpers to choose secure parameters.
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Set the plaintext modulus (the "space" for plaintext data)
    // We'll use a 20-bit prime. This means we can encrypt numbers
    // up to this value (approx 1 million).
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create the "SEALContext", which validates all our parameters
    SEALContext context(parms);
    timer.stop("1. Parameter Setup");

    cout << "--- 1. Parameters Set ---" << endl;
    cout << "Security Level (Poly Modulus Degree): " << poly_modulus_degree << endl;

    // --- 2. Generate Keys ---
    timer.start();
    // A KeyGenerator is created from the SEALContext
    KeyGenerator keygen(context);

    // Create the public key (pk)
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Create the secret key (sk)
    SecretKey secret_key = keygen.secret_key();

    // Create relinearization keys (rlk) - necessary for multiplication
    // We'll create them now, even though we only add in this example.
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    timer.stop("2. Key Generation (PK, SK, RLK)");

    cout << "--- 2. Keys Generated ---" << endl;


    // --- 3. Encrypt Plaintext Data ---
    // Create the "smart grid data"
    int64_t usage_data_1 = 100;
    int64_t usage_data_2 = 50;
    cout << "--- 3. Plaintext Data ---" << endl;
    cout << "Smart Meter 1 Usage: " << usage_data_1 << endl;
    cout << "Smart Meter 2 Usage: " << usage_data_2 << endl;

    // Create helper objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // To encrypt, we first encode the data into a "Plaintext" object
    Plaintext pt_1(to_string(usage_data_1));
    Plaintext pt_2(to_string(usage_data_2));

    // Now we can encrypt the plaintexts into "Ciphertext" objects
    Ciphertext ct_1;
    Ciphertext ct_2;
    timer.start();
    encryptor.encrypt(pt_1, ct_1);
    timer.stop("3. Encryption of Data 1");
    timer.start();
    encryptor.encrypt(pt_2, ct_2);
    timer.stop("3. Encryption of Data 2");

    cout << "Data Encrypted." << endl;

    // --- 4. Perform Homomorphic Computation (Addition) ---

    // We homomorphically add the two ciphertexts (ct_1 + ct_2)
    // and store the result in a new ciphertext, ct_result.
    Ciphertext ct_result;
    timer.start();
    evaluator.add(ct_1, ct_2, ct_result);
    timer.stop("4. Homomorphic Addition");

    cout << "--- 4. Homomorphic Addition Performed ---" << endl;


    // --- 5. Decrypt the Result ---

    // Create a new plaintext to hold the decrypted result
    Plaintext pt_result;
    decryptor.decrypt(ct_result, pt_result);

    cout << "--- 5. Result Decrypted ---" << endl;

    // --- 6. Verify the Answer ---

    // We must decode the plaintext object back into a number
    int64_t final_result = stoll(pt_result.to_string());

    cout << "--- 6. Verification ---" << endl;
    cout << "Expected Result: " << (usage_data_1 + usage_data_2) << endl;
    cout << "Computed Result: " << final_result << endl;

    // Check if the computation was correct!
    if (final_result == (usage_data_1 + usage_data_2)) {
        cout << "Success! The homomorphic addition worked." << endl;
    } else {
        cout << "Failure! The computation was incorrect." << endl;
    }

    return 0;
}