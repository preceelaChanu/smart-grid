"""
Day 6 - Step 4: Parameter Sensitivity Analysis
Compare different CKKS parameter configurations for optimization
"""

import seal
from ckks_encoder import CKKSSmartMeterEncoder
from benchmark import CKKSBenchmark
import json
import pandas as pd

def test_coefficient_modulus_configurations():
    """
    Test different coefficient modulus chains to optimize ciphertext size
    and performance while maintaining security
    """
    
    print("\n" + "#"*70)
    print("DAY 6 - STEP 4: PARAMETER SENSITIVITY ANALYSIS")
    print("#"*70)
    
    # Test configurations with different coefficient modulus chains
    # All maintain ~128-bit security level for poly_modulus_degree=8192
    configurations = [
        {
            'name': 'Current (4 primes: 60-40-40-60)',
            'poly_modulus_degree': 8192,
            'coeff_modulus': [60, 40, 40, 60],
            'description': 'Your current configuration'
        },
        {
            'name': 'Optimized (3 primes: 60-40-60)',
            'poly_modulus_degree': 8192,
            'coeff_modulus': [60, 40, 60],
            'description': 'Reduced modulus chain for smaller ciphertext'
        },
        {
            'name': 'High Depth (5 primes: 60-40-40-40-60)',
            'poly_modulus_degree': 8192,
            'coeff_modulus': [60, 40, 40, 40, 60],
            'description': 'More primes for deeper computations'
        },
        {
            'name': 'Compact (2 primes: 60-60)',
            'poly_modulus_degree': 8192,
            'coeff_modulus': [60, 60],
            'description': 'Minimal chain for smallest ciphertext'
        }
    ]
    
    all_results = []
    
    for config in configurations:
        print(f"\n{'='*70}")
        print(f"Testing: {config['name']}")
        print(f"Description: {config['description']}")
        print(f"{'='*70}")
        
        try:
            # Create custom SEAL context with specific parameters
            parms = seal.EncryptionParameters(seal.scheme_type.ckks)
            parms.set_poly_modulus_degree(config['poly_modulus_degree'])
            parms.set_coeff_modulus(
                seal.CoeffModulus.Create(
                    config['poly_modulus_degree'],
                    config['coeff_modulus']
                )
            )
            
            context = seal.SEALContext(parms)
            
            # Check if parameters are valid
            if not context.parameters_set():
                print("✗ Invalid parameters - skipping")
                continue
            
            print(f"✓ Parameters valid")
            
            # Generate keys for this configuration
            keygen = seal.KeyGenerator(context)
            public_key = keygen.create_public_key()
            secret_key = keygen.secret_key()
            
            # Initialize components
            encoder = seal.CKKSEncoder(context)
            encryptor = seal.Encryptor(context, public_key)
            decryptor = seal.Decryptor(context, secret_key)
            evaluator = seal.Evaluator(context)
            
            print(f"✓ Slot count: {encoder.slot_count()}")
            
            # Create benchmark
            benchmark = CKKSBenchmark(
                context=context,
                encoder=encoder,
                encryptor=encryptor,
                decryptor=decryptor,
                evaluator=evaluator
            )
            
            # Run benchmark on 1000 data points
            result = benchmark.benchmark_full_pipeline(data_size=1000, iterations=10)
            
            # Add configuration info to result
            result['config_name'] = config['name']
            result['coeff_modulus'] = config['coeff_modulus']
            result['num_primes'] = len(config['coeff_modulus'])
            
            all_results.append(result)
            
            print(f"✓ Benchmark complete:")
            print(f"  Total latency: {result['total_pipeline_latency_ms']:.4f} ms")
            print(f"  Ciphertext size: {result['encryption']['ciphertext_size_kb']:.2f} KB")
            print(f"  Expansion ratio: {result['expansion_ratio']:.2f}x")
            
        except Exception as e:
            print(f"✗ Error with configuration: {e}")
            continue
    
    # Comparison analysis
    if len(all_results) > 0:
        print("\n" + "="*70)
        print("CONFIGURATION COMPARISON")
        print("="*70)
        
        # Create comparison DataFrame
        comparison = pd.DataFrame([
            {
                'Configuration': r['config_name'],
                'Primes': r['num_primes'],
                'Encoding (ms)': r['encoding']['mean_ms'],
                'Encryption (ms)': r['encryption']['mean_ms'],
                'Decryption (ms)': r['decryption']['mean_ms'],
                'Decoding (ms)': r['decoding']['mean_ms'],
                'Total (ms)': r['total_pipeline_latency_ms'],
                'Ciphertext (KB)': r['encryption']['ciphertext_size_kb'],
                'Expansion': f"{r['expansion_ratio']:.1f}x",
                'Target Met': '✓' if r['meets_200ms_target'] else '✗'
            }
            for r in all_results
        ])
        
        print("\n" + comparison.to_string(index=False))
        
        # Find optimal configuration
        print("\n" + "="*70)
        print("OPTIMIZATION ANALYSIS")
        print("="*70)
        
        # Best for latency
        best_latency = min(all_results, key=lambda x: x['total_pipeline_latency_ms'])
        print(f"\n✓ Fastest configuration: {best_latency['config_name']}")
        print(f"  Latency: {best_latency['total_pipeline_latency_ms']:.4f} ms")
        
        # Best for ciphertext size
        best_size = min(all_results, key=lambda x: x['encryption']['ciphertext_size_kb'])
        print(f"\n✓ Smallest ciphertext: {best_size['config_name']}")
        print(f"  Size: {best_size['encryption']['ciphertext_size_kb']:.2f} KB")
        print(f"  Expansion: {best_size['expansion_ratio']:.2f}x")
        
        # Best balance (weighted score)
        for r in all_results:
            # Normalize metrics (lower is better)
            latency_score = r['total_pipeline_latency_ms'] / 200  # Normalize to target
            size_score = r['encryption']['ciphertext_size_kb'] / 500  # Normalize to reasonable size
            r['balance_score'] = (latency_score + size_score) / 2
        
        best_balance = min(all_results, key=lambda x: x['balance_score'])
        print(f"\n✓ Best balanced configuration: {best_balance['config_name']}")
        print(f"  Latency: {best_balance['total_pipeline_latency_ms']:.4f} ms")
        print(f"  Size: {best_balance['encryption']['ciphertext_size_kb']:.2f} KB")
        
        # Recommendations
        print("\n" + "="*70)
        print("RECOMMENDATIONS")
        print("="*70)
        
        current = all_results[0]  # First config is current
        
        if best_size['encryption']['ciphertext_size_kb'] < current['encryption']['ciphertext_size_kb'] * 0.8:
            reduction = (1 - best_size['encryption']['ciphertext_size_kb'] / current['encryption']['ciphertext_size_kb']) * 100
            print(f"\n1. Consider switching to '{best_size['config_name']}'")
            print(f"   → Reduces ciphertext size by {reduction:.1f}%")
            print(f"   → Maintains excellent performance")
        
        if all(r['meets_200ms_target'] for r in all_results):
            print(f"\n2. All configurations meet 200ms target")
            print(f"   → Can prioritize ciphertext size optimization")
            print(f"   → Smaller ciphertexts improve network efficiency")
        
        print(f"\n3. For smart grid edge deployment:")
        print(f"   → Use '{best_balance['config_name']}' for best overall performance")
        print(f"   → Balances latency and bandwidth requirements")
        
        # Save results
        with open('day6_parameter_sensitivity.json', 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n✓ Detailed results saved to: day6_parameter_sensitivity.json")
    
    else:
        print("\n✗ No valid configurations to compare")
    
    return all_results


def test_polynomial_modulus_degrees():
    """
    Test different polynomial modulus degrees (security/performance trade-off)
    """
    
    print("\n" + "="*70)
    print("POLYNOMIAL MODULUS DEGREE ANALYSIS")
    print("="*70)
    
    configurations = [
        {
            'name': '4096 (Lower Security)',
            'poly_modulus_degree': 4096,
            'coeff_modulus': [60, 40, 40, 60]
        },
        {
            'name': '8192 (Medium Security - Current)',
            'poly_modulus_degree': 8192,
            'coeff_modulus': [60, 40, 40, 60]
        },
        {
            'name': '16384 (High Security)',
            'poly_modulus_degree': 16384,
            'coeff_modulus': [60, 40, 40, 40, 40, 60]
        }
    ]
    
    results = []
    
    for config in configurations:
        print(f"\nTesting: {config['name']}")
        
        try:
            encoder_system = CKKSSmartMeterEncoder(
                poly_modulus_degree=config['poly_modulus_degree'],
                keys_dir=f"keys_{config['poly_modulus_degree']}"
            )
            
            benchmark = CKKSBenchmark(
                context=encoder_system.context,
                encoder=encoder_system.encoder,
                encryptor=encoder_system.encryptor,
                decryptor=encoder_system.decryptor,
                evaluator=encoder_system.evaluator
            )
            
            result = benchmark.benchmark_full_pipeline(data_size=1000, iterations=5)
            result['config_name'] = config['name']
            results.append(result)
            
            print(f"  Latency: {result['total_pipeline_latency_ms']:.4f} ms")
            print(f"  Ciphertext: {result['encryption']['ciphertext_size_kb']:.2f} KB")
            
        except Exception as e:
            print(f"  Error: {e}")
    
    return results


if __name__ == "__main__":
    # Test 1: Coefficient modulus optimization
    print("\n" + "#"*70)
    print("TEST 1: COEFFICIENT MODULUS OPTIMIZATION")
    print("#"*70)
    coeff_results = test_coefficient_modulus_configurations()
    
    # Test 2: Polynomial degree comparison
    print("\n" + "#"*70)
    print("TEST 2: POLYNOMIAL MODULUS DEGREE COMPARISON")
    print("#"*70)
    degree_results = test_polynomial_modulus_degrees()
    
    print("\n" + "#"*70)
    print("DAY 6 - STEP 4: PARAMETER SENSITIVITY ANALYSIS COMPLETE")
    print("#"*70)
