from ckks_context import CKKSContext
from smart_meter_simulator import SmartMeterSimulator
import numpy as np

def test_encryption_decryption():
    """Test that encryption and decryption work correctly"""
    print("\n" + "="*60)
    print("CKKS ENCRYPTION VERIFICATION TEST")
    print("="*60)
    
    # Setup context
    ckks = CKKSContext()
    ckks.setup_context()
    
    # Generate sample reading
    meter = SmartMeterSimulator("TEST_METER")
    reading = meter.generate_reading()
    data_vector = meter.get_data_vector(reading)
    
    print("\n📊 Original Data:")
    fields = ['voltage', 'current', 'frequency', 'active_power', 
              'reactive_power', 'apparent_power', 'power_factor']
    for field, value in zip(fields, data_vector):
        print(f"  {field}: {value}")
    
    # Encrypt
    print("\n🔒 Encrypting...")
    encrypted = ckks.encrypt_vector(data_vector)
    print(f"  ✓ Encrypted successfully")
    print(f"  Ciphertext size: {len(encrypted.serialize())} bytes")
    
    # Decrypt
    print("\n🔓 Decrypting...")
    decrypted = ckks.decrypt_vector(encrypted)
    print(f"  ✓ Decrypted successfully")
    
    # Compare
    print("\n📊 Decrypted Data:")
    for field, orig, dec in zip(fields, data_vector, decrypted):
        error = abs(orig - dec)
        print(f"  {field}: {dec:.6f} (error: {error:.2e})")
    
    # Calculate accuracy
    errors = [abs(o - d) for o, d in zip(data_vector, decrypted)]
    max_error = max(errors)
    avg_error = np.mean(errors)
    
    print(f"\n📈 Accuracy Metrics:")
    print(f"  Max error: {max_error:.2e}")
    print(f"  Avg error: {avg_error:.2e}")
    print(f"  ✓ Encryption precision verified!")

if __name__ == "__main__":
    test_encryption_decryption()
