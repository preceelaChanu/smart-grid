import tenseal as ts
import pickle
import os

class CKKSContext:
    """Manages CKKS encryption context and keys"""
    
    def __init__(self):
        self.context = None
        self.public_context = None
        
    def setup_context(self, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60], 
                     scale=2**40):
        """
        Initialize CKKS context with security parameters
        
        Parameters:
        - poly_modulus_degree: Security parameter (8192 or 16384)
        - coeff_mod_bit_sizes: Coefficient modulus chain
        - scale: Encoding scale for precision
        """
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=coeff_mod_bit_sizes
        )
        self.context.generate_galois_keys()
        self.context.global_scale = scale
        
        # Create public context (no secret key)
        self.public_context = self.context.copy()
        self.public_context.make_context_public()
        
        print(f"✓ CKKS Context initialized")
        print(f"  - Polynomial modulus degree: {poly_modulus_degree}")
        print(f"  - Scale: 2^{scale.bit_length()-1}")
        
        return self.context
    
    def save_context(self, filepath="keys/context.bin"):
        """Save the context to file"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(self.context.serialize())
        print(f"✓ Context saved to {filepath}")
    
    def load_context(self, filepath="keys/context.bin"):
        """Load context from file"""
        with open(filepath, 'rb') as f:
            self.context = ts.context_from(f.read())
        print(f"✓ Context loaded from {filepath}")
        return self.context
    
    def encrypt_vector(self, data):
        """Encrypt a vector of floating-point values"""
        if self.context is None:
            raise ValueError("Context not initialized. Call setup_context() first.")
        return ts.ckks_vector(self.context, data)
    
    def decrypt_vector(self, encrypted_data):
        """Decrypt a CKKS vector"""
        return encrypted_data.decrypt()
