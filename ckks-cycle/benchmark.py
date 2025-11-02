"""
Day 6: CKKS Encryption Benchmarking Framework
Performance testing for encryption latency and ciphertext size analysis
"""

import time
import gc
import json
import numpy as np
from typing import Dict, List, Tuple
from datetime import datetime
import sys

from ckks_encoder import CKKSSmartMeterEncoder

class CKKSBenchmark:
    """
    Comprehensive benchmarking framework for CKKS encryption operations
    """
    
    def __init__(self, context, encoder, encryptor, decryptor, evaluator=None):
        """
        Initialize benchmark with CKKS components from ckks_encoder.py
        
        Args:
            context: SEAL/OpenFHE context object
            encoder: CKKSEncoder instance
            encryptor: Encryptor instance
            decryptor: Decryptor instance
            evaluator: Evaluator instance (optional, for future use)
        """
        self.context = context
        self.encoder = encoder
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.evaluator = evaluator
        
        # Store benchmark results
        self.results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'python_version': sys.version,
                'test_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            'benchmarks': []
        }
    
    def generate_test_data(self, size: int) -> np.ndarray:
        """
        Generate synthetic smart grid data for testing
        
        Args:
            size: Number of data points to generate
            
        Returns:
            numpy array of synthetic meter readings
        """
        # Simulate voltage/power readings (normalized between -2 and 2)
        return np.random.uniform(-2.0, 2.0, size)
    
    def benchmark_encoding(self, data: np.ndarray, iterations: int = 10) -> Dict:
        """
        Benchmark encoding phase: float array → plaintext
        
        Args:
            data: Input data array
            iterations: Number of benchmark repetitions
            
        Returns:
            Dictionary with timing statistics
        """
        gc.disable()  # Disable garbage collection for consistent timing
        times = []
        plaintext = None
        
        # Use the scale we defined (2^40)
        scale = pow(2.0, 40)

        # Get the maximum number of values we can encode at once
        max_slots = self.encoder.slot_count()
        
        # If data size exceeds slots, only encode up to max_slots
        data = data[:max_slots]
        
        # Warn if we had to truncate
        if len(data) < len(data):
            print(f"⚠️  Warning: Data truncated to {max_slots} points due to slot count limitation")

        # Warm-up run to eliminate initialization overhead
        _ = self.encoder.encode(data, scale)
        
        for _ in range(iterations):
            start = time.perf_counter()
            plaintext = self.encoder.encode(data, scale)
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to milliseconds
        
        gc.enable()
        
        return {
            'phase': 'encoding',
            'mean_ms': np.mean(times),
            'median_ms': np.median(times),
            'std_ms': np.std(times),
            'min_ms': np.min(times),
            'max_ms': np.max(times),
            'iterations': iterations
        }
    
    def benchmark_encryption(self, plaintext, iterations: int = 10) -> Dict:
        """
        Benchmark encryption phase: plaintext → ciphertext
        
        Args:
            plaintext: Encoded plaintext object
            iterations: Number of benchmark repetitions
            
        Returns:
            Dictionary with timing and size statistics
        """
        gc.disable()
        times = []
        ciphertext = None
        
        # Warm-up
        _ = self.encryptor.encrypt(plaintext)
        
        for _ in range(iterations):
            start = time.perf_counter()
            ciphertext = self.encryptor.encrypt(plaintext)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        gc.enable()
        
        # Measure ciphertext size
        ciphertext_size = self._get_ciphertext_size(ciphertext)
        
        return {
            'phase': 'encryption',
            'mean_ms': np.mean(times),
            'median_ms': np.median(times),
            'std_ms': np.std(times),
            'min_ms': np.min(times),
            'max_ms': np.max(times),
            'ciphertext_size_bytes': ciphertext_size,
            'ciphertext_size_kb': ciphertext_size / 1024,
            'iterations': iterations
        }, ciphertext
    
    def benchmark_decryption(self, ciphertext, iterations: int = 10) -> Dict:
        """
        Benchmark decryption phase: ciphertext → plaintext
        
        Args:
            ciphertext: Encrypted ciphertext object
            iterations: Number of benchmark repetitions
            
        Returns:
            Dictionary with timing statistics
        """
        gc.disable()
        times = []
        
        # Warm-up
        _ = self.decryptor.decrypt(ciphertext)
        
        for _ in range(iterations):
            start = time.perf_counter()
            plaintext_result = self.decryptor.decrypt(ciphertext)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        gc.enable()
        
        return {
            'phase': 'decryption',
            'mean_ms': np.mean(times),
            'median_ms': np.median(times),
            'std_ms': np.std(times),
            'min_ms': np.min(times),
            'max_ms': np.max(times),
            'iterations': iterations
        }
    
    def benchmark_decoding(self, plaintext, iterations: int = 10) -> Dict:
        """
        Benchmark decoding phase: plaintext → float array
        
        Args:
            plaintext: Decrypted plaintext object
            iterations: Number of benchmark repetitions
            
        Returns:
            Dictionary with timing statistics
        """
        gc.disable()
        times = []
        
        # Warm-up
        _ = self.encoder.decode(plaintext)
        
        for _ in range(iterations):
            start = time.perf_counter()
            result = self.encoder.decode(plaintext)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        gc.enable()
        
        return {
            'phase': 'decoding',
            'mean_ms': np.mean(times),
            'median_ms': np.median(times),
            'std_ms': np.std(times),
            'min_ms': np.min(times),
            'max_ms': np.max(times),
            'iterations': iterations
        }
    
    def benchmark_full_pipeline(self, data_size: int, iterations: int = 10) -> Dict:
        """
        Benchmark complete encode-encrypt-decrypt-decode pipeline
        
        Args:
            data_size: Number of data points to process
            iterations: Number of benchmark repetitions
            
        Returns:
            Comprehensive benchmark results dictionary
        """
        print(f"\n{'='*70}")
        print(f"BENCHMARKING: {data_size} data points")
        print(f"{'='*70}")
        
        # Generate test data
        test_data = self.generate_test_data(data_size)
        
        # Check if data size exceeds available slots
        max_slots = self.encoder.slot_count()
        if data_size > max_slots:
            print(f"⚠️  Note: Data size ({data_size}) exceeds available slots ({max_slots})")
            print(f"   Benchmarking with {max_slots} points instead")
            test_data = test_data[:max_slots]
            data_size = max_slots
        
        # Benchmark each phase
        print("→ Benchmarking encoding...")
        encoding_results = self.benchmark_encoding(test_data, iterations)
        
        # Get plaintext for next phases using scale = 2^40
        plaintext = self.encoder.encode(test_data, pow(2.0, 40))
        
        print("→ Benchmarking encryption...")
        encryption_results, ciphertext = self.benchmark_encryption(plaintext, iterations)
        
        print("→ Benchmarking decryption...")
        decryption_results = self.benchmark_decryption(ciphertext, iterations)
        
        # Get decrypted plaintext for decoding
        decrypted_plaintext = self.decryptor.decrypt(ciphertext)
        
        print("→ Benchmarking decoding...")
        decoding_results = self.benchmark_decoding(decrypted_plaintext, iterations)
        
        # Calculate total pipeline latency
        total_latency = (
            encoding_results['mean_ms'] +
            encryption_results['mean_ms'] +
            decryption_results['mean_ms'] +
            decoding_results['mean_ms']
        )
        
        # Calculate expansion ratio
        plaintext_size = data_size * 8  # 8 bytes per float64
        expansion_ratio = encryption_results['ciphertext_size_bytes'] / plaintext_size
        
        benchmark_result = {
            'data_size': data_size,
            'plaintext_size_bytes': plaintext_size,
            'plaintext_size_kb': plaintext_size / 1024,
            'encoding': encoding_results,
            'encryption': encryption_results,
            'decryption': decryption_results,
            'decoding': decoding_results,
            'total_pipeline_latency_ms': total_latency,
            'expansion_ratio': expansion_ratio,
            'meets_200ms_target': total_latency < 200
        }
        
        self.results['benchmarks'].append(benchmark_result)
        
        return benchmark_result
    
    def run_benchmark_suite(self, data_sizes: List[int] = None, iterations: int = 10):
        """
        Run complete benchmark suite across multiple data sizes
        
        Args:
            data_sizes: List of data sizes to test (default: [128, 512, 1024, 2048, 4096])
            iterations: Number of repetitions per test
        """
        if data_sizes is None:
            # Use powers of 2 up to the maximum slot count
            max_slots = self.encoder.slot_count()
            data_sizes = [
                size for size in [128, 512, 1024, 2048, 4096]
                if size <= max_slots
            ]
        
        print("\n" + "="*70)
        print("DAY 6: CKKS ENCRYPTION BENCHMARK SUITE")
        print("="*70)
        print(f"Test configurations: {len(data_sizes)} data sizes")
        print(f"Iterations per test: {iterations}")
        print(f"Target latency: <200ms per operation")
        print("="*70)
        
        for size in data_sizes:
            self.benchmark_full_pipeline(size, iterations)
        
        self._print_summary()
    
    def _get_ciphertext_size(self, ciphertext) -> int:
        """
        Calculate serialized ciphertext size in bytes
        
        Args:
            ciphertext: Ciphertext object
            
        Returns:
            Size in bytes
        """
        # For Microsoft SEAL, we use save_size() to get the serialized size
        return ciphertext.save_size()
    
    def _print_summary(self):
        """Print formatted summary of all benchmark results"""
        print("\n" + "="*70)
        print("BENCHMARK SUMMARY")
        print("="*70)
        
        for result in self.results['benchmarks']:
            print(f"\nData Size: {result['data_size']} points")
            print(f"  Encoding:    {result['encoding']['mean_ms']:.4f} ms")
            print(f"  Encryption:  {result['encryption']['mean_ms']:.4f} ms")
            print(f"  Decryption:  {result['decryption']['mean_ms']:.4f} ms")
            print(f"  Decoding:    {result['decoding']['mean_ms']:.4f} ms")
            print(f"  Total:       {result['total_pipeline_latency_ms']:.4f} ms")
            print(f"  Ciphertext:  {result['encryption']['ciphertext_size_kb']:.2f} KB")
            print(f"  Expansion:   {result['expansion_ratio']:.2f}x")
            print(f"  Target Met:  {'✓ PASS' if result['meets_200ms_target'] else '✗ FAIL'}")
    
    def save_results(self, filename: str = 'day6_benchmark_results.json'):
        """
        Save benchmark results to JSON file
        
        Args:
            filename: Output filename
        """
        # Convert NumPy values to native Python types
        def convert_to_native(obj):
            if isinstance(obj, (np.integer, np.floating)):
                return float(obj)
            elif isinstance(obj, np.bool_):
                return bool(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {key: convert_to_native(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_native(item) for item in obj]
            return obj

        # Convert results to JSON-serializable format
        json_results = convert_to_native(self.results)
        
        with open(filename, 'w') as f:
            json.dump(json_results, f, indent=2)
        print(f"\n✓ Results saved to: {filename}")


# Usage example
if __name__ == "__main__":
    # Initialize CKKS components
    encoder_system = CKKSSmartMeterEncoder(poly_modulus_degree=8192, keys_dir='keys')
    
    # Create benchmark instance with components from the encoder system
    benchmark = CKKSBenchmark(
        context=encoder_system.context,
        encoder=encoder_system.encoder,
        encryptor=encoder_system.encryptor,
        decryptor=encoder_system.decryptor,
        evaluator=encoder_system.evaluator
    )
    
    # Run benchmark suite with different data sizes
    benchmark.run_benchmark_suite(
        data_sizes=[100, 500, 1000, 5000, 10000],
        iterations=10
    )
    
    # Save results to JSON file
    benchmark.save_results('ckks_benchmark_results.json')
