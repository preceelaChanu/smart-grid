"""
Day 6 - Step 3: Benchmark Results Analysis
Analyze performance metrics and identify optimization opportunities
"""

import json
import numpy as np
import pandas as pd

def analyze_benchmark_results(results_file='day6_benchmark_results.json'):
    """
    Analyze benchmark results and generate insights
    
    Args:
        results_file: Path to benchmark results JSON
    """
    # Load results
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    print("\n" + "="*70)
    print("DAY 6: BENCHMARK ANALYSIS")
    print("="*70)
    
    # Extract metadata
    metadata = results['metadata']
    print(f"\nTest Configuration:")
    print(f"  Polynomial Modulus Degree: {metadata['poly_modulus_degree']}")
    print(f"  Scale: {metadata['scale']}")
    print(f"  Slot Count: {metadata['slot_count']}")
    print(f"  Test Date: {metadata['test_date']}")
    
    # Create DataFrame for analysis
    benchmarks = results['benchmarks']
    df = pd.DataFrame([
        {
            'data_size': b['data_size'],
            'encoding_ms': b['encoding']['mean_ms'],
            'encryption_ms': b['encryption']['mean_ms'],
            'decryption_ms': b['decryption']['mean_ms'],
            'decoding_ms': b['decoding']['mean_ms'],
            'total_ms': b['total_pipeline_latency_ms'],
            'ciphertext_kb': b['encryption']['ciphertext_size_kb'],
            'expansion_ratio': b['expansion_ratio'],
            'meets_target': b['meets_200ms_target']
        }
        for b in benchmarks
    ])
    
    print("\n" + "="*70)
    print("PERFORMANCE METRICS")
    print("="*70)
    print(df.to_string(index=False))
    
    # Calculate latency breakdown percentages
    print("\n" + "="*70)
    print("LATENCY BREAKDOWN (Average across all tests)")
    print("="*70)
    avg_encoding = df['encoding_ms'].mean()
    avg_encryption = df['encryption_ms'].mean()
    avg_decryption = df['decryption_ms'].mean()
    avg_decoding = df['decoding_ms'].mean()
    total_avg = avg_encoding + avg_encryption + avg_decryption + avg_decoding
    
    print(f"  Encoding:    {avg_encoding:.4f} ms ({avg_encoding/total_avg*100:.1f}%)")
    print(f"  Encryption:  {avg_encryption:.4f} ms ({avg_encryption/total_avg*100:.1f}%)")
    print(f"  Decryption:  {avg_decryption:.4f} ms ({avg_decryption/total_avg*100:.1f}%)")
    print(f"  Decoding:    {avg_decoding:.4f} ms ({avg_decoding/total_avg*100:.1f}%)")
    print(f"  Total:       {total_avg:.4f} ms")
    
    # Identify bottlenecks
    print("\n" + "="*70)
    print("BOTTLENECK ANALYSIS")
    print("="*70)
    bottleneck_phases = []
    if avg_encryption > avg_encoding and avg_encryption > avg_decryption:
        bottleneck_phases.append("Encryption")
    if avg_decryption > avg_encryption and avg_decryption > avg_encoding:
        bottleneck_phases.append("Decryption")
    
    if bottleneck_phases:
        print(f"  Primary bottleneck(s): {', '.join(bottleneck_phases)}")
    else:
        print("  No clear bottleneck - performance is balanced")
    
    # Target achievement
    print("\n" + "="*70)
    print("TARGET ACHIEVEMENT (200ms)")
    print("="*70)
    passed = df['meets_target'].sum()
    total = len(df)
    print(f"  Tests passed: {passed}/{total} ({passed/total*100:.1f}%)")
    
    if passed < total:
        failed = df[~df['meets_target']]
        print(f"  Failed data sizes: {list(failed['data_size'].values)}")
    
    # Scalability analysis
    print("\n" + "="*70)
    print("SCALABILITY ANALYSIS")
    print("="*70)
    if len(df) > 1:
        # Calculate latency growth rate
        small_size = df.iloc[0]
        large_size = df.iloc[-1]
        size_increase = large_size['data_size'] / small_size['data_size']
        latency_increase = large_size['total_ms'] / small_size['total_ms']
        
        print(f"  Data size increase: {size_increase:.2f}x")
        print(f"  Latency increase: {latency_increase:.2f}x")
        print(f"  Scaling efficiency: {(size_increase/latency_increase)*100:.1f}%")
    
    # Ciphertext expansion
    print("\n" + "="*70)
    print("CIPHERTEXT EXPANSION")
    print("="*70)
    avg_expansion = df['expansion_ratio'].mean()
    print(f"  Average expansion ratio: {avg_expansion:.2f}x")
    print(f"  Average ciphertext size: {df['ciphertext_kb'].mean():.2f} KB")
    
    # Recommendations
    print("\n" + "="*70)
    print("OPTIMIZATION RECOMMENDATIONS")
    print("="*70)
    
    recommendations = []
    
    if not all(df['meets_target']):
        recommendations.append("⚠ Reduce polynomial modulus degree to improve latency")
    
    if avg_encryption/total_avg > 0.4:
        recommendations.append("⚠ Encryption is >40% of total time - consider parameter tuning")
    
    if avg_expansion > 100:
        recommendations.append("⚠ High ciphertext expansion - optimize coefficient modulus chain")
    
    if avg_decoding/total_avg > 0.3:
        recommendations.append("✓ Decoding overhead is acceptable")
    
    if passed == total:
        recommendations.append("✓ All tests meet 200ms target - excellent performance!")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)
    
    return df

if __name__ == "__main__":
    df = analyze_benchmark_results('day6_benchmark_results.json')
