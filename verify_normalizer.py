import time
from app.services.normalizer import Normalizer

def main():
    print("Testing Normalizer Engine...")
    normalizer = Normalizer()
    
    # 1. Homoglyph attack
    homoglyph_input = "admіn"  # U+0456 (Cyrillic i)
    t0 = time.perf_counter()
    res1 = normalizer.normalize(homoglyph_input)
    t1 = time.perf_counter()
    assert res1 == "admin", f"Expected 'admin', got '{res1}'"
    print(f"✅ Homoglyph check passed ({ (t1-t0)*1000:.3f} ms)")

    # 2. Zero-width attack
    zero_width_input = "h\u200bell\u200bo"
    t0 = time.perf_counter()
    res2 = normalizer.normalize(zero_width_input)
    t1 = time.perf_counter()
    assert res2 == "hello", f"Expected 'hello', got '{res2}'"
    print(f"✅ Zero-width check passed ({ (t1-t0)*1000:.3f} ms)")

    # 3. Base64
    base64_input = "YWRtaW4="
    t0 = time.perf_counter()
    res3 = normalizer.normalize(base64_input)
    t1 = time.perf_counter()
    assert res3 == "admin", f"Expected 'admin', got '{res3}'"
    print(f"✅ Base64 check passed ({ (t1-t0)*1000:.3f} ms)")

    # 4. Hex
    hex_input = "61646d696e"
    t0 = time.perf_counter()
    res4 = normalizer.normalize(hex_input)
    t1 = time.perf_counter()
    assert res4 == "admin", f"Expected 'admin', got '{res4}'"
    print(f"✅ Hex check passed ({ (t1-t0)*1000:.3f} ms)")

    # 5. Nested (Base64 encoded Hex of "admin")
    nested_input = "NjE2NDZkNjk2ZQ=="
    t0 = time.perf_counter()
    res5 = normalizer.normalize(nested_input)
    t1 = time.perf_counter()
    assert res5 == "admin", f"Expected 'admin', got '{res5}'"
    print(f"✅ Nested obfuscation check passed ({ (t1-t0)*1000:.3f} ms)")
    
    print("\nAll Normalizer checks passed successfully!")

if __name__ == "__main__":
    main()
