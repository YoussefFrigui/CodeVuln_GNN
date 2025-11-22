import os
import json
import re
import requests

INPUT_FILE = 'outputs/datasets/python_advisories_with_commits.json'
OUTPUT_FILE = 'outputs/results/commit_data_results.json'
GITHUB_TOKEN = os.environ.get('GITHUB_PAT')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'}

import time

def get_commit_diff(commit_url, max_retries=3, delay=2):
    match = re.search(r'github\.com/([^/]+)/([^/]+)/(commit|pull)/(\w+)', commit_url)
    if not match:
        return None
    owner, repo, url_type, ref = match.groups()
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}"
    if url_type == 'pull':
        pr_api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{ref}/commits"
        for attempt in range(max_retries):
            try:
                response = requests.get(pr_api_url, headers=HEADERS)
                if response.status_code == 200 and response.json():
                    last_commit_sha = response.json()[-1]['sha']
                    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{last_commit_sha}"
                    break
                else:
                    time.sleep(delay)
            except Exception as e:
                print(f"Error fetching PR commits: {e}")
                time.sleep(delay)
        else:
            return None
    for attempt in range(max_retries):
        try:
            response = requests.get(api_url, headers=HEADERS)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to fetch {api_url}: {response.status_code}")
                time.sleep(delay)
        except Exception as e:
            print(f"Error fetching commit: {e}")
            time.sleep(delay)
    return None

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        advisories = json.load(f)
    results = []
    # Resume support: load existing results if file exists
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            try:
                results = json.load(f)
            except Exception:
                results = []
        processed_ids = set(r['advisory_id'] for r in results)
    else:
        processed_ids = set()
    for idx, adv in enumerate(advisories):
        if adv['id'] in processed_ids:
            continue
        print(f"Processing {idx+1}/{len(advisories)}: {adv['id']}")
        commit_data = get_commit_diff(adv['url'])
        if commit_data:
            results.append({
                "advisory_id": adv['id'],
                "cwe_ids": adv['cwe_ids'],
                "summary": adv['summary'],
                "commit_url": adv['url'],
                "commit_data": commit_data
            })
        # Save progress every 10 advisories
        if len(results) % 10 == 0:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
        time.sleep(1)  # Delay between requests
    print(f"Fetched commit data for {len(results)} advisories.")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"Saved commit data to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
