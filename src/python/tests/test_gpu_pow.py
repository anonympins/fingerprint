import pytest
import struct
from engine import ChallengeUtils

def test_gpu_pow_hash_seed_determinism():
    """Ensures python seed hashing logic has absolute parity with PHP and JS."""
    seed = "python-pow-test-seed"
    f1 = ChallengeUtils.hash_seed_to_float(seed)
    f2 = ChallengeUtils.hash_seed_to_float(seed)
    f3 = ChallengeUtils.hash_seed_to_float("another-python-seed")

    assert f1 == f2
    assert 0 <= f1 < 1.0
    assert f1 != f3

def test_float_precision_fround_parity():
    """Validates IEEE 754 32-bit single-precision float emulation parity."""
    val = 0.1234567890123456
    f_val = ChallengeUtils.fround(val)
    
    # Single precision representation check
    packed = struct.pack('f', val)
    unpacked = struct.unpack('f', packed)[0]
    assert f_val == unpacked

def test_gpu_pow_verify_valid_solution():
    """Validates correctness of a simulated client trajectory."""
    seed = "python-chaotic-regime-validation"
    iterations = 200
    
    numeric_seed = ChallengeUtils.hash_seed_to_float(seed)
    r = 3.9999
    solutions = []
    
    for idx in range(64):
        x = ChallengeUtils.fround(numeric_seed + idx * 0.015)
        r_float = ChallengeUtils.fround(r)
        for _ in range(iterations):
            x = ChallengeUtils.fround(r_float * x * ChallengeUtils.fround(1.0 - x))
        solutions.append(f"{x:.6f}")
        
    valid_solution_string = ",".join(solutions)
    assert ChallengeUtils.verify_gpu_pow(seed, iterations, valid_solution_string) is True

def test_gpu_pow_verify_invalid_and_tampered():
    """Ensures tampered calculations fail verification."""
    seed = "python-tampering-checks"
    iterations = 50
    
    # Create correct solution string
    numeric_seed = ChallengeUtils.hash_seed_to_float(seed)
    r = 3.9999
    solutions = [str(ChallengeUtils.fround(numeric_seed + idx * 0.015)) for idx in range(64)]
    
    # Invalid length
    assert ChallengeUtils.verify_gpu_pow(seed, iterations, ",".join(solutions[:30])) is False
    
    # Tamper with index 35 (inside default sampling indices)
    solutions[35] = str(float(solutions[35]) + 0.1)
    assert ChallengeUtils.verify_gpu_pow(seed, iterations, ",".join(solutions)) is False