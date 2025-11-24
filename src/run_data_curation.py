"""
Run Data Curation Pipeline

This script orchestrates the complete data curation process:
1. Collect from multiple sources (GitHub, NVD, synthetic)
2. Validate and filter for quality
3. Balance across CWE types and complexity
4. Export high-quality diverse dataset

Usage:
    python src/run_data_curation.py
    
    # With NVD API key (recommended)
    NVD_API_KEY=your_key python src/run_data_curation.py
"""

import sys
import os
import yaml
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.abspath('.'))

from src.data_quality.data_curator import DataCurator
from src.data_quality.validator import validate_dataset


def load_config():
    """Load configuration from YAML."""
    with open('configs/base_config.yaml', 'r') as f:
        return yaml.safe_load(f)


def run_curation_pipeline(config):
    """Run complete data curation pipeline."""
    
    print("="*60)
    print("🎯 HIGH-QUALITY VULNERABILITY DATA CURATION")
    print("="*60)
    
    # Initialize curator
    curator_config = {
        'min_quality_score': config['dataset']['quality']['min_quality_score'],
        'output_dir': 'outputs/datasets/curated'
    }
    
    curator = DataCurator(curator_config)
    
    # Step 1: Collect from GitHub Advisories (existing)
    print("\n" + "="*60)
    print("📦 STEP 1: Loading existing GitHub Advisory data")
    print("="*60)
    
    advisories_path = config['data']['advisories_path']
    if os.path.exists(advisories_path):
        import json
        with open(advisories_path, 'r') as f:
            advisory_data = json.load(f)
        
        added = 0
        for item in advisory_data:
            from src.data_quality.data_curator import VulnerabilityExample
            
            # Extract severity - it's a list of CVSS objects in the JSON
            severity_value = 'MEDIUM'  # default
            severity_data = item.get('severity', [])
            if isinstance(severity_data, list) and len(severity_data) > 0:
                # Extract CVSS score to determine severity level
                cvss_score = severity_data[0].get('score', '')
                if 'CVSS:' in cvss_score:
                    # Parse base score from CVSS string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
                    # High = 7.0-8.9, Critical = 9.0-10.0, Medium = 4.0-6.9, Low = 0.1-3.9
                    if '/C:H/I:H/A:H' in cvss_score or '/C:H' in cvss_score:
                        severity_value = 'HIGH'
                    elif '/C:L' in cvss_score or '/C:N' in cvss_score:
                        severity_value = 'LOW'
                else:
                    severity_value = 'MEDIUM'
            elif isinstance(severity_data, str):
                severity_value = severity_data
            
            # Extract CWE ID
            cwe_id = None
            cwe_ids = item.get('cwe_ids', [])
            if cwe_ids and len(cwe_ids) > 0:
                cwe_id = cwe_ids[0]  # Take first CWE
            
            # Extract description
            description = item.get('summary', '') or item.get('description', '')
            
            example = VulnerabilityExample(
                id=item.get('advisory_id', 'unknown'),
                source='github_advisory',
                cwe_id=cwe_id,
                severity=severity_value,
                vulnerable_code=item.get('vulnerable_code', ''),
                fixed_code=item.get('fixed_code'),
                description=description,
                has_context=True,
                metadata={
                    'commit_url': item.get('commit_url'),
                    'filename': item.get('filename'),
                    'published': item.get('published')
                }
            )
            
            if curator.add_example(example):
                added += 1
        
        print(f"✓ Loaded {added} examples from GitHub Advisories")
    else:
        print(f"⚠️  No GitHub Advisory data found at {advisories_path}")
        print("   Run: python run_pipeline.py --step preprocess")
    
    # Step 2: Generate Synthetic Vulnerabilities
    if config['dataset']['diversity']['include_synthetic']:
        print("\n" + "="*60)
        print("🔬 STEP 2: Generating Synthetic Vulnerabilities")
        print("="*60)
        
        synthetic_count = config['dataset']['diversity']['synthetic_count']
        curator.generate_synthetic_vulnerabilities(count=synthetic_count)
    
    # Step 3: Collect from NVD (if API key provided)
    if config['data']['sources']['nvd']:
        print("\n" + "="*60)
        print("🌐 STEP 3: Collecting from National Vulnerability Database")
        print("="*60)
        
        nvd_api_key = os.environ.get('NVD_API_KEY')
        if nvd_api_key:
            curator.collect_from_nvd(api_key=nvd_api_key, max_results=500)
        else:
            print("⚠️  NVD_API_KEY not set. Skipping NVD collection.")
            print("   Get API key: https://nvd.nist.gov/developers/request-an-api-key")
    
    # Step 4: Export curated dataset
    print("\n" + "="*60)
    print("💾 STEP 4: Exporting Curated Dataset")
    print("="*60)
    
    curated_path = config['data']['curated_dataset_path']
    curator.export_dataset(curated_path)
    
    # Step 5: Validate and balance
    print("\n" + "="*60)
    print("✅ STEP 5: Validating and Balancing Dataset")
    print("="*60)
    
    validation_config = {
        'min_loc': config['dataset']['quality']['min_loc'],
        'max_loc': config['dataset']['quality']['max_loc'],
    }
    
    validated_path = config['data']['validated_dataset_path']
    validate_dataset(curated_path, validated_path, validation_config)
    
    # Final statistics
    print("\n" + "="*60)
    print("📊 FINAL STATISTICS")
    print("="*60)
    
    stats = curator.get_statistics()
    
    print(f"\n✓ Total examples: {stats['total_examples']}")
    print(f"✓ Average quality score: {stats['avg_quality_score']:.3f}")
    print(f"✓ Examples with fixes: {stats['has_fixes']}")
    print(f"✓ Unique CWE types: {stats['cwe_types']}")
    
    print(f"\n📈 Data Sources:")
    for source, count in stats['sources'].items():
        print(f"   {source}: {count}")
    
    print(f"\n🎯 Top 10 CWE Types:")
    for cwe, count in sorted(stats['cwe_distribution'].items(), 
                             key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {cwe}: {count}")
    
    print(f"\n" + "="*60)
    print("✅ DATA CURATION COMPLETE!")
    print("="*60)
    print(f"\n📁 Curated dataset: {curated_path}")
    print(f"📁 Validated dataset: {validated_path}")
    print(f"\n💡 Next steps:")
    print(f"   1. Review the curated data quality")
    print(f"   2. Run dataset creation: python run_pipeline.py --step dataset")
    print(f"   3. Train model with high-quality data")
    

def main():
    """Main entry point."""
    try:
        config = load_config()
        run_curation_pipeline(config)
    except KeyboardInterrupt:
        print("\n\n⚠️  Curation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error during curation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
