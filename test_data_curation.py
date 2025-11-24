"""
Quick test of data curation system

Run this to verify the curation system works before full pipeline.
"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from src.data_quality.data_curator import DataCurator, VulnerabilityExample
from src.data_quality.validator import CodeQualityValidator


def test_synthetic_generation():
    """Test synthetic vulnerability generation."""
    print("=" * 60)
    print("🧪 Testing Synthetic Vulnerability Generation")
    print("=" * 60)
    
    config = {'min_quality_score': 0.4}
    curator = DataCurator(config)
    
    # Generate small batch
    added = curator.generate_synthetic_vulnerabilities(count=20)
    
    stats = curator.get_statistics()
    
    print(f"\n✓ Generated: {added} examples")
    print(f"✓ CWE types: {stats['cwe_types']}")
    print(f"✓ Avg quality: {stats['avg_quality_score']:.3f}")
    
    # Show one example
    if curator.examples:
        example = curator.examples[0]
        print(f"\n📝 Sample Example:")
        print(f"   CWE: {example.cwe_id}")
        print(f"   Quality: {example.quality_score:.2f}")
        print(f"   LOC: {example.loc}")
        print(f"\n   Vulnerable Code:")
        print("   " + "\n   ".join(example.vulnerable_code.split('\n')[:5]))
    
    assert added > 0, "Should generate at least some examples"
    print("\n✅ Synthetic generation works!")
    return True


def test_validation():
    """Test code quality validation."""
    print("\n" + "=" * 60)
    print("🧪 Testing Code Quality Validation")
    print("=" * 60)
    
    validator = CodeQualityValidator()
    
    # Test 1: Valid code
    valid_code = """
def search_users(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    
    is_valid, metrics = validator.validate_example(valid_code)
    print(f"\n✓ Valid code test: {'PASS' if is_valid else 'FAIL'}")
    print(f"   Quality score: {metrics.get('quality_score', 0):.2f}")
    print(f"   LOC: {metrics.get('loc', 0)}")
    
    # Test 2: Invalid code (syntax error)
    invalid_code = """
def broken_function(:
    this is not valid python
"""
    
    is_valid2, metrics2 = validator.validate_example(invalid_code)
    print(f"\n✓ Invalid code test: {'PASS' if not is_valid2 else 'FAIL'}")
    print(f"   Reason: {metrics2.get('reason', 'unknown')}")
    
    # Test 3: Too short
    short_code = "x = 1"
    is_valid3, metrics3 = validator.validate_example(short_code)
    print(f"\n✓ Short code test: {'PASS' if not is_valid3 else 'FAIL'}")
    print(f"   Reason: {metrics3.get('reason', 'unknown')}")
    
    assert is_valid and not is_valid2 and not is_valid3
    print("\n✅ Validation works correctly!")
    return True


def test_quality_scoring():
    """Test quality score calculation."""
    print("\n" + "=" * 60)
    print("🧪 Testing Quality Scoring")
    print("=" * 60)
    
    # High quality example
    high_quality = VulnerabilityExample(
        id="test_1",
        source="test",
        cwe_id="CWE-89",
        severity="HIGH",
        vulnerable_code="""def query_user(user_id):
    query = "SELECT * FROM users WHERE id=" + str(user_id)
    cursor.execute(query)
    return cursor.fetchone()""",
        fixed_code="""def query_user(user_id):
    query = "SELECT * FROM users WHERE id=%s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()""",
        description="SQL injection vulnerability in user query function",
        has_context=True
    )
    
    print(f"\n✓ High-quality example:")
    print(f"   Quality score: {high_quality.quality_score:.2f}")
    print(f"   Has fix: {high_quality.fixed_code is not None}")
    print(f"   Has CWE: {high_quality.cwe_id is not None}")
    
    # Low quality example
    low_quality = VulnerabilityExample(
        id="test_2",
        source="test",
        cwe_id=None,
        severity="MEDIUM",
        vulnerable_code="x = eval(input())",
        fixed_code=None,
        description="Bad",
        has_context=False
    )
    
    print(f"\n✓ Low-quality example:")
    print(f"   Quality score: {low_quality.quality_score:.2f}")
    print(f"   Has fix: {low_quality.fixed_code is not None}")
    print(f"   Has CWE: {low_quality.cwe_id is not None}")
    
    assert high_quality.quality_score > low_quality.quality_score
    print("\n✅ Quality scoring works!")
    return True


def test_deduplication():
    """Test hash-based deduplication."""
    print("\n" + "=" * 60)
    print("🧪 Testing Deduplication")
    print("=" * 60)
    
    config = {'min_quality_score': 0.3}
    curator = DataCurator(config)
    
    # Same code, different formatting
    code1 = "def func():\n    return 1"
    code2 = "def func():\n        return 1"  # Extra spaces
    
    ex1 = VulnerabilityExample(
        id="dup_1", source="test", cwe_id="CWE-1", severity="LOW",
        vulnerable_code=code1, fixed_code=None, description="Test"
    )
    
    ex2 = VulnerabilityExample(
        id="dup_2", source="test", cwe_id="CWE-1", severity="LOW",
        vulnerable_code=code2, fixed_code=None, description="Test"
    )
    
    added1 = curator.add_example(ex1)
    added2 = curator.add_example(ex2)  # Should be deduplicated
    
    print(f"\n✓ First example added: {added1}")
    print(f"✓ Duplicate rejected: {not added2}")
    print(f"✓ Total examples: {len(curator.examples)}")
    
    assert added1 and not added2, "Should reject duplicate"
    print("\n✅ Deduplication works!")
    return True


def run_all_tests():
    """Run all tests."""
    print("\n" + "🚀" * 30)
    print(" DATA CURATION SYSTEM TEST SUITE")
    print("🚀" * 30 + "\n")
    
    tests = [
        ("Synthetic Generation", test_synthetic_generation),
        ("Validation", test_validation),
        ("Quality Scoring", test_quality_scoring),
        ("Deduplication", test_deduplication),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"\n❌ {name} FAILED")
        except Exception as e:
            failed += 1
            print(f"\n❌ {name} FAILED with error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"📊 TEST RESULTS: {passed}/{len(tests)} passed")
    print("=" * 60)
    
    if failed == 0:
        print("\n✅ All tests passed! System is ready.")
        print("\n💡 Next step: Run full curation")
        print("   python src/run_data_curation.py")
    else:
        print(f"\n❌ {failed} test(s) failed. Check errors above.")
        return False
    
    return True


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
