"""Show exactly what code snippets are failing conversion and why."""

import json
import ast
import sys
sys.path.insert(0, 'src')

from data_processing.graph_utils import fix_incomplete_code

# Load advisories
adv = json.load(open('outputs/datasets/processed_advisories_with_code.json'))

fails = []
for a in adv:
    code = a.get('vulnerable_code', '')
    fixed = fix_incomplete_code(code)
    if not fixed:
        # Try to get the actual error
        try:
            ast.parse(code)
            error = "Unknown (parsed but fix_incomplete_code returned None)"
        except SyntaxError as e:
            error = f"{e.msg} at line {e.lineno}"
        
        fails.append({
            'id': a.get('id', '?'),
            'code': code,
            'error': error
        })

print(f"Total failures: {len(fails)}")
print()
print("=" * 60)
print("TOP 10 FAILED CODE SNIPPETS WITH ERRORS")
print("=" * 60)

for i, f in enumerate(fails[:10]):
    print(f"\n--- Failure {i+1}: {f['id']} ---")
    print(f"Error: {f['error']}")
    print(f"Code preview:")
    print("-" * 40)
    # Show first 300 chars
    preview = f['code'][:300].replace('\n', '\n  ')
    print(f"  {preview}")
    if len(f['code']) > 300:
        print("  ...")
    print()
