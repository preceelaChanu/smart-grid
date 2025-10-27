import seal
import numpy as np
import pandas as pd
import os

class CKKSSmartMeterEncoder:
    def __init__(self, poly_modulus_degree=8192, keys_dir='keys'):
        """
        Initialize CKKS encoder with optional pre-existing keys
        
        Args:
            poly_modulus_degree: Polynomial modulus degree (default: 8192)
            keys_dir: Directory containing pre-generated keys
        """
        # Set polynomial modulus degree
        self.poly_modulus_degree = poly_modulus_degree
        self.parms = seal.EncryptionParameters(seal.scheme_type.ckks)
        self.parms.set_poly_modulus_degree(poly_modulus_degree)
        self.parms.set_coeff_modulus(
            seal.CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60])
        )
        
        # Create SEAL context
        self.context = seal.SEALContext(self.parms)
        print(f"✓ SEAL context created")
        print(f"  Parameters valid: {self.context.parameters_set()}")
        
        # Initialize encoder
        self.encoder = seal.CKKSEncoder(self.context)
        self.scale = pow(2.0, 40)  # High-precision scale
        self.slot_count = self.encoder.slot_count()
        
        print(f"✓ CKKS Encoder initialized")
        print(f"  Available slots: {self.slot_count}")
        
        # Load or generate keys
        self.keys_dir = keys_dir
        self.load_or_generate_keys()
        
    def load_or_generate_keys(self):
        """Load pre-generated keys or generate new ones"""
        public_key_path = os.path.join(self.keys_dir, 'public.key')
        secret_key_path = os.path.join(self.keys_dir, 'secret.key')
        relin_key_path = os.path.join(self.keys_dir, 'relin.key')
        
        if os.path.exists(public_key_path) and os.path.exists(secret_key_path):
            print(f"✓ Loading pre-generated keys from {self.keys_dir}/")
            
            try:
                # Load keys
                self.public_key = seal.PublicKey()
                self.secret_key = seal.SecretKey()
                self.relin_keys = seal.RelinKeys()
                
                self.public_key.load(self.context, public_key_path)
                self.secret_key.load(self.context, secret_key_path)
                if os.path.exists(relin_key_path):
                    self.relin_keys.load(self.context, relin_key_path)
                        
                print("✓ Keys loaded successfully")
                self._initialize_crypto_objects()
            except RuntimeError as e:
                print(f"! Error loading keys: {e}")
                print("✓ Generating new keys instead...")
                self._generate_and_save_keys()
        else:
            self._generate_and_save_keys()
            
    def _initialize_crypto_objects(self):
        """Initialize encryptor, decryptor, and evaluator"""
        self.encryptor = seal.Encryptor(self.context, self.public_key)
        self.decryptor = seal.Decryptor(self.context, self.secret_key)
        self.evaluator = seal.Evaluator(self.context)
    
    def _generate_and_save_keys(self):
        """Helper method to generate and save new keys"""
        # Generate keys
        keygen = seal.KeyGenerator(self.context)
        self.public_key = keygen.create_public_key()
        self.secret_key = keygen.secret_key()
        self.relin_keys = keygen.create_relin_keys()
        
        # Create directory if it doesn't exist
        os.makedirs(self.keys_dir, exist_ok=True)
        
        # Save keys using the new API
        self.public_key.save(os.path.join(self.keys_dir, 'public.key'))
        self.secret_key.save(os.path.join(self.keys_dir, 'secret.key'))
        self.relin_keys.save(os.path.join(self.keys_dir, 'relin.key'))
        
        print(f"✓ New keys generated and saved to {self.keys_dir}/")
        
        # Initialize crypto objects
        self._initialize_crypto_objects()
        
    def load_smart_meter_data(self, data_path, acorn_group=None, max_rows=None):
        """
        Load and preprocess London smart meter data
        
        Args:
            data_path: Path to daily_dataset CSV file
            acorn_group: Filter by ACORN group (e.g., 'Affluent', 'Adversity', 'Comfortable')
            max_rows: Limit number of rows to load
        
        Returns:
            Preprocessed numpy array of energy values
        """
        print(f"\n{'='*70}")
        print("LOADING SMART METER DATA")
        print(f"{'='*70}")
        
        # Load daily dataset
        df_daily = pd.read_csv(data_path, nrows=max_rows)
        print(f"✓ Loaded {len(df_daily)} rows from {data_path}")
        
        # Load household information
        households_path = 'informations_households.csv'
        if os.path.exists(households_path):
            df_households = pd.read_csv(households_path)
            df_combined = df_daily.merge(df_households, on='LCLid', how='left')
            print(f"✓ Merged with household information")
            
            # Filter by ACORN group if specified
            if acorn_group:
                df_combined = df_combined[df_combined['Acorn_grouped'] == acorn_group]
                print(f"✓ Filtered to ACORN group: {acorn_group}")
                print(f"  Households: {df_combined['LCLid'].nunique()}")
                print(f"  Data points: {len(df_combined)}")
            
            df_data = df_combined
        else:
            print("⚠ Household information not found, using daily data only")
            df_data = df_daily
        
        # Extract energy values
        energy_values = df_data['energy_mean'].values
        
        # Handle missing values
        energy_values = np.nan_to_num(energy_values, nan=0.0)
        
        print(f"\n✓ Extracted energy consumption data:")
        print(f"  Total values: {len(energy_values)}")
        print(f"  Range: [{energy_values.min():.4f}, {energy_values.max():.4f}] kWh")
        print(f"  Mean: {energy_values.mean():.4f} kWh")
        print(f"  Std: {energy_values.std():.4f} kWh")
        
        return energy_values
    
    def normalize_data(self, data):
        """Normalize data for better CKKS precision"""
        mean = np.mean(data)
        std = np.std(data)
        normalized = (data - mean) / (std + 1e-8)
        
        print(f"\n✓ Data normalized:")
        print(f"  Original range: [{data.min():.4f}, {data.max():.4f}]")
        print(f"  Normalized range: [{normalized.min():.4f}, {normalized.max():.4f}]")
        
        return normalized, mean, std
    
    def prepare_data_vector(self, data):
        """Prepare data vector for CKKS encoding"""
        # Limit to available slots
        max_points = min(len(data), self.slot_count)
        data_vector = data[:max_points]
        
        # Pad with zeros if needed
        if len(data_vector) < self.slot_count:
            padding = np.zeros(self.slot_count - len(data_vector))
            data_vector = np.concatenate([data_vector, padding])
        
        # Ensure float64
        data_vector = np.array(data_vector, dtype=np.float64)
        
        print(f"\n✓ Data vector prepared:")
        print(f"  Actual values: {max_points}")
        print(f"  Padding: {self.slot_count - max_points}")
        print(f"  Total slots: {self.slot_count}")
        
        return data_vector, max_points
    
    def encode_data(self, data):
        """Encode data to CKKS plaintext"""
        plain = self.encoder.encode(data, self.scale)
        print(f"✓ Data encoded to plaintext")
        return plain
    
    def decode_data(self, plain):
        """Decode CKKS plaintext to data"""
        decoded = self.encoder.decode(plain)
        return decoded
    
    def encrypt_data(self, plain):
        """Encrypt plaintext to ciphertext"""
        encrypted = self.encryptor.encrypt(plain)
        print(f"✓ Plaintext encrypted")
        return encrypted
    
    def decrypt_data(self, encrypted):
        """Decrypt ciphertext to plaintext"""
        decrypted = self.decryptor.decrypt(encrypted)
        print(f"✓ Ciphertext decrypted")
        return decrypted
    
    def validate_encoding(self, original, decoded, actual_count):
        """Validate encoding accuracy"""
        original_vals = original[:actual_count]
        decoded_vals = decoded[:actual_count]
        
        error = np.mean(np.abs(original_vals - decoded_vals))
        max_error = np.max(np.abs(original_vals - decoded_vals))
        
        print(f"\n{'='*70}")
        print("ENCODING VALIDATION")
        print(f"{'='*70}")
        print(f"Mean absolute error: {error:.10f}")
        print(f"Max absolute error: {max_error:.10f}")
        print(f"Sample comparison (first 5 values):")
        print(f"  Original: {original_vals[:5]}")
        print(f"  Decoded:  {decoded_vals[:5]}")
        
        return error
    
    def full_pipeline_test(self, data_path, acorn_group=None, max_rows=1000):
        """
        Complete Day 5 pipeline: Load → Normalize → Encode → Encrypt → Decrypt → Decode
        
        Args:
            data_path: Path to daily dataset CSV
            acorn_group: Optional ACORN group filter
            max_rows: Limit rows for testing
        """
        print(f"\n{'#'*70}")
        print("DAY 5: CKKS ENCODER FULL PIPELINE TEST")
        print(f"{'#'*70}")
        
        # Step 1: Load smart meter data
        energy_data = self.load_smart_meter_data(data_path, acorn_group, max_rows)
        
        # Step 2: Normalize data
        normalized_data, mean, std = self.normalize_data(energy_data)
        
        # Step 3: Prepare data vector
        data_vector, actual_count = self.prepare_data_vector(normalized_data)
        
        # Step 4: Encode
        print(f"\n{'='*70}")
        print("ENCODING")
        print(f"{'='*70}")
        plain = self.encode_data(data_vector)
        
        # Step 5: Validate encoding
        decoded_check = self.decode_data(plain)
        encoding_error = self.validate_encoding(data_vector, decoded_check, actual_count)
        
        # Step 6: Encrypt
        print(f"\n{'='*70}")
        print("ENCRYPTION")
        print(f"{'='*70}")
        encrypted = self.encrypt_data(plain)
        
        # Step 7: Decrypt
        print(f"\n{'='*70}")
        print("DECRYPTION")
        print(f"{'='*70}")
        decrypted = self.decrypt_data(encrypted)
        
        # Step 8: Decode and validate
        final_decoded = self.decode_data(decrypted)
        total_error = self.validate_encoding(data_vector, final_decoded, actual_count)
        
        # Summary
        print(f"\n{'#'*70}")
        print("DAY 5 IMPLEMENTATION COMPLETE")
        print(f"{'#'*70}")
        print(f"✓ Data points processed: {actual_count}")
        print(f"✓ Encoding error: {encoding_error:.10f}")
        print(f"✓ Total pipeline error: {total_error:.10f}")
        print(f"✓ Status: {'PASSED ✓' if total_error < 1e-6 else 'CHECK PARAMETERS ⚠'}")
        
        # Save results
        results = {
            "date": "2025-10-27",
            "poly_modulus_degree": self.poly_modulus_degree,
            "scale": self.scale,
            "slot_count": self.slot_count,
            "data_points": int(actual_count),
            "acorn_group": acorn_group if acorn_group else "All",
            "encoding_error": float(encoding_error),
            "total_error": float(total_error),
            "original_mean": float(mean),
            "original_std": float(std)
        }
        
        import json
        with open('day5_ckks_results.json', 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n✓ Results saved to: day5_ckks_results.json")
        
        return results


# Main execution
if __name__ == "__main__":
    # Initialize encoder with pre-existing keys
    encoder_system = CKKSSmartMeterEncoder(poly_modulus_degree=8192, keys_dir='keys')
    
    # Run full pipeline test
    results = encoder_system.full_pipeline_test(
        data_path='/workspaces/smart-grid/ckks-cycle/daily-dataset/block_0.csv',
        acorn_group='Affluent',  # Change to None for all households
        max_rows=1000
    )
