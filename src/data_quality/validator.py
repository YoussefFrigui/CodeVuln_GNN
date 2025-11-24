"""
Data Quality Validator

Validates and filters vulnerability examples based on multiple quality criteria.
"""

import ast
import re
from typing import List, Dict, Tuple
from radon.complexity import cc_visit
from radon.metrics import mi_visit


class CodeQualityValidator:
    """Validate code quality and filter low-quality examples."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.min_loc = self.config.get('min_loc', 5)
        self.max_loc = self.config.get('max_loc', 500)
        self.min_complexity = self.config.get('min_complexity', 1)
        
    def validate_example(self, code: str, metadata: Dict = None) -> Tuple[bool, Dict]:
        """
        Validate a code example.
        
        Returns:
            (is_valid, quality_metrics)
        """
        metrics = {}
        issues = []
        
        # Check 1: Must be non-empty
        if not code or len(code.strip()) < 10:
            return False, {'reason': 'Code too short'}
        
        # Check 2: Must be valid Python syntax
        try:
            tree = ast.parse(code)
            metrics['syntax_valid'] = True
        except SyntaxError as e:
            return False, {'reason': f'Syntax error: {e}'}
        
        # Check 3: LOC within reasonable bounds
        loc = len([line for line in code.split('\n') if line.strip()])
        metrics['loc'] = loc
        
        if loc < self.min_loc:
            issues.append(f'LOC too small: {loc}')
        if loc > self.max_loc:
            issues.append(f'LOC too large: {loc}')
        
        # Check 4: Must contain actual code (not just comments)
        code_lines = [line for line in code.split('\n') 
                     if line.strip() and not line.strip().startswith('#')]
        if len(code_lines) < 3:
            return False, {'reason': 'Too few code lines (mostly comments)'}
        
        # Check 5: Complexity (at least one function)
        try:
            complexity = cc_visit(code)
            if complexity:
                avg_complexity = sum(c.complexity for c in complexity) / len(complexity)
                metrics['complexity'] = avg_complexity
                
                if avg_complexity < self.min_complexity:
                    issues.append(f'Complexity too low: {avg_complexity}')
            else:
                # No functions found
                if 'def ' not in code and 'class ' not in code:
                    issues.append('No functions or classes found')
        except Exception as e:
            issues.append(f'Complexity analysis failed: {e}')
        
        # Check 6: Maintainability Index
        try:
            mi_score = mi_visit(code, True)
            if mi_score:
                metrics['maintainability_index'] = mi_score
        except:
            pass
        
        # Check 7: Must not be a trivial example
        trivial_patterns = [
            r'^\s*pass\s*$',
            r'^\s*print\s*\(',
            r'^\s*x\s*=\s*\d+\s*$'
        ]
        
        if any(re.match(pattern, code.strip(), re.MULTILINE) for pattern in trivial_patterns):
            if loc < 10:
                return False, {'reason': 'Trivial example'}
        
        # Check 8: Specific vulnerability indicators (optional bonus)
        vuln_indicators = [
            'execute',  # SQL
            'eval', 'exec',  # Code injection
            'pickle.load',  # Deserialization
            'os.system', 'subprocess',  # Command injection
            'open(',  # File operations
            'requests.get', 'requests.post',  # SSRF
            'hashlib.md5', 'hashlib.sha1',  # Weak crypto
        ]
        
        has_vuln_indicator = any(indicator in code for indicator in vuln_indicators)
        metrics['has_vuln_indicator'] = has_vuln_indicator
        
        # Calculate overall score
        score = 1.0
        if issues:
            score -= 0.2 * len(issues)
        if has_vuln_indicator:
            score += 0.2
        
        metrics['quality_score'] = max(0, min(1, score))
        metrics['issues'] = issues
        
        # Decision
        is_valid = len(issues) <= 1 and metrics['quality_score'] > 0.5
        
        return is_valid, metrics
    
    def validate_pair(self, vulnerable_code: str, fixed_code: str) -> Tuple[bool, Dict]:
        """
        Validate a vulnerable/fixed code pair.
        
        Ensures:
        - Both are valid
        - They're sufficiently different
        - Fixed version doesn't just delete vulnerable code
        """
        # Validate both individually
        vuln_valid, vuln_metrics = self.validate_example(vulnerable_code)
        if not vuln_valid:
            return False, {'reason': 'Vulnerable code invalid', 'vuln_metrics': vuln_metrics}
        
        fixed_valid, fixed_metrics = self.validate_example(fixed_code)
        if not fixed_valid:
            return False, {'reason': 'Fixed code invalid', 'fixed_metrics': fixed_metrics}
        
        # Check they're actually different
        similarity = self._compute_similarity(vulnerable_code, fixed_code)
        
        if similarity > 0.95:
            return False, {'reason': 'Codes too similar', 'similarity': similarity}
        
        if similarity < 0.3:
            return False, {'reason': 'Codes too different (likely unrelated)', 'similarity': similarity}
        
        # Check fixed isn't just empty
        if len(fixed_code.strip()) < len(vulnerable_code.strip()) * 0.3:
            return False, {'reason': 'Fixed code suspiciously shorter'}
        
        return True, {
            'similarity': similarity,
            'vuln_metrics': vuln_metrics,
            'fixed_metrics': fixed_metrics
        }
    
    def _compute_similarity(self, code1: str, code2: str) -> float:
        """Compute normalized similarity between two code snippets."""
        # Simple token-based similarity
        tokens1 = set(re.findall(r'\w+', code1.lower()))
        tokens2 = set(re.findall(r'\w+', code2.lower()))
        
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2
        
        return len(intersection) / len(union) if union else 0.0


class DatasetBalancer:
    """Balance dataset across vulnerability types and complexity."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
    def balance_by_cwe(self, examples: List[Dict], 
                       max_per_cwe: int = 100) -> List[Dict]:
        """
        Balance examples across CWE types.
        
        Prevents over-representation of common vulnerabilities.
        """
        from collections import defaultdict
        import random
        
        cwe_groups = defaultdict(list)
        
        for example in examples:
            cwe = example.get('cwe_id', 'unknown')
            cwe_groups[cwe].append(example)
        
        balanced = []
        
        for cwe, cwe_examples in cwe_groups.items():
            if len(cwe_examples) > max_per_cwe:
                # Sample highest quality examples
                cwe_examples.sort(key=lambda x: x.get('quality_score', 0), reverse=True)
                sampled = cwe_examples[:max_per_cwe]
            else:
                sampled = cwe_examples
            
            balanced.extend(sampled)
        
        random.shuffle(balanced)
        return balanced
    
    def balance_by_complexity(self, examples: List[Dict], 
                             bins: int = 5) -> List[Dict]:
        """Balance examples by code complexity."""
        import numpy as np
        
        # Sort by complexity
        examples_with_complexity = [
            ex for ex in examples 
            if ex.get('complexity') is not None
        ]
        
        if not examples_with_complexity:
            return examples
        
        complexities = [ex['complexity'] for ex in examples_with_complexity]
        
        # Create bins
        bin_edges = np.percentile(complexities, np.linspace(0, 100, bins + 1))
        
        balanced = []
        min_per_bin = len(examples_with_complexity) // bins
        
        for i in range(bins):
            bin_examples = [
                ex for ex in examples_with_complexity
                if bin_edges[i] <= ex['complexity'] < bin_edges[i + 1]
            ]
            
            if len(bin_examples) > min_per_bin:
                bin_examples.sort(key=lambda x: x.get('quality_score', 0), reverse=True)
                balanced.extend(bin_examples[:min_per_bin])
            else:
                balanced.extend(bin_examples)
        
        return balanced


def validate_dataset(input_path: str, output_path: str, config: Dict = None):
    """
    Validate and filter an entire dataset.
    
    Args:
        input_path: Path to input JSON dataset
        output_path: Path to save validated dataset
        config: Validation configuration
    """
    import json
    from pathlib import Path
    
    print("🔍 Validating dataset...")
    
    validator = CodeQualityValidator(config)
    
    # Load dataset
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    examples = data.get('examples', [])
    
    valid_examples = []
    invalid_count = 0
    validation_stats = {
        'total': len(examples),
        'valid': 0,
        'invalid': 0,
        'reasons': {}
    }
    
    for example in examples:
        code = example.get('vulnerable_code', '')
        
        is_valid, metrics = validator.validate_example(code)
        
        if is_valid:
            example['validation_metrics'] = metrics
            valid_examples.append(example)
            validation_stats['valid'] += 1
        else:
            invalid_count += 1
            validation_stats['invalid'] += 1
            reason = metrics.get('reason', 'unknown')
            validation_stats['reasons'][reason] = validation_stats['reasons'].get(reason, 0) + 1
    
    # Balance the dataset
    balancer = DatasetBalancer(config)
    balanced_examples = balancer.balance_by_cwe(valid_examples)
    
    # Save validated dataset
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    output_data = {
        'examples': balanced_examples,
        'validation_stats': validation_stats,
        'metadata': data.get('metadata', {})
    }
    
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n✓ Validation complete")
    print(f"  Total: {validation_stats['total']}")
    print(f"  Valid: {validation_stats['valid']}")
    print(f"  Invalid: {validation_stats['invalid']}")
    print(f"  Balanced: {len(balanced_examples)}")
    
    if validation_stats['reasons']:
        print(f"\nInvalid reasons:")
        for reason, count in sorted(validation_stats['reasons'].items(), 
                                    key=lambda x: x[1], reverse=True):
            print(f"  {reason}: {count}")
    
    print(f"\n📁 Validated dataset saved to: {output_path}")


if __name__ == '__main__':
    # Example usage
    validate_dataset(
        'outputs/datasets/curated_vulnerabilities.json',
        'outputs/datasets/validated_vulnerabilities.json'
    )
