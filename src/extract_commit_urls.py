import json
import re

INPUT_FILE = 'python_advisories.json'
OUTPUT_FILE = 'python_advisories_with_commits.json'

def find_commit_url(advisory):
    commit_urls = []
    if not advisory.get('references'):
        return None
    for ref in advisory['references']:
        url = ref.get('url')
        if url:
            # Regex to find GitHub commit or pull request URLs
            if re.search(r'github\.com/.+/.+/commit/\w+', url):
                commit_urls.append(url)
            elif re.search(r'github\.com/.+/.+/pull/\d+', url):
                commit_urls.append(url)
    return commit_urls[0] if commit_urls else None

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        advisories = json.load(f)
    advisories_with_commit = []
    for adv in advisories:
        commit_url = find_commit_url(adv)
        if commit_url:
            advisories_with_commit.append({
                "id": adv.get('id'),
                "summary": adv.get('summary'),
                "cwe_ids": adv.get('database_specific', {}).get('cwe_ids', []),
                "url": commit_url
            })
    print(f"Found {len(advisories_with_commit)} advisories with a potential fix commit URL.")
    if advisories_with_commit:
        print(json.dumps(advisories_with_commit[0], indent=2))
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(advisories_with_commit, f, indent=2)
    print(f"Saved advisories with commit URLs to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
