Excellent question! This is the most critical and often the most difficult step in building a vulnerability detection model. You've correctly identified that having a massive corpus of general code (like CodeSearchNet) is only half the battle. You need the labeled "positive" samples (vulnerable code).

Let's break down how you can find, and more realistically, *create* this labeled dataset.

### The Challenge: Why It's Hard to Find a "Perfect" Dataset
Ready-made, large-scale, accurately labeled datasets for Python vulnerabilities are rare. The reasons are:
*   **Labor-intensive:** Manually finding and verifying vulnerabilities is slow and requires security expertise.
*   **Ambiguity:** The definition of a "vulnerability" can be fuzzy. Is a hardcoded password a vulnerability in the same way a Remote Code Execution (RCE) flaw is?
*   **Domain Shift:** Vulnerabilities discovered in old versions of libraries (e.g., Python 2.7) might not be relevant today.

Therefore, the best approach is often a combination of using existing resources and generating your own labeled data.

---

### Strategy 1: Find Existing (but likely imperfect) Datasets

These are good starting points, but you'll likely need to supplement them.

1.  **SARD (Software Assurance Reference Dataset):**
    *   **What it is:** A project by NIST that is the most famous reference for vulnerable code. It contains thousands of synthetic test cases for various vulnerabilities (CWEs).
    *   **Pros:** Clearly labeled with vulnerability types (CWEs), has "good" (patched) and "bad" (vulnerable) versions.
    *   **Cons:** **Heavily focused on C, C++, and Java.** The Python section is much smaller and may not cover the wide range of modern web framework vulnerabilities. It's a great place to look but won't be enough on its own.
    *   **Link:** [NIST SARD Project](https://samate.nist.gov/SARD/)

2.  **Devign Dataset & Big-Vul:**
    *   **What they are:** Research datasets created by mining open-source projects. They are often used in academic papers for "vulnerability detection in source code" tasks.
    *   **Pros:** Based on real-world code from actual commits that fixed vulnerabilities.
    *   **Cons:** Primarily focused on C and C++. You'll have to check if they have Python subsets or if their methodology can be reapplied to Python.
    *   **Links:**
        *   [Big-Vul Dataset](https://github.com/Zeo-shark/Big-Vul)
        *   [Devign on GitHub](https://sites.google.com/view/devign) (Their data is often linked from their papers/sites)

3.  **GitHub Security Advisories Database:**
    *   **What it is:** A database of security advisories reported on GitHub.
    *   **Pros:** Contains real-world vulnerabilities, often linked to the exact commit that fixed them.
    *   **Cons:** This is not a "dataset" but a *source of data*. You would need to write scripts to parse the advisories, find the linked repositories and commits, and extract the "before" (vulnerable) and "after" (patched) code snippets.
    *   **Link:** [GitHub Advisory Database](https://github.com/advisories)

---

### Strategy 2: Create Your Own Labeled Dataset (Highly Recommended)

This is where the real work begins, but it yields the best results. You'll create pairs of `(vulnerable_code, non_vulnerable_code)`.

#### Method A: Mining Git Commits (Most Powerful Method)

The core idea is to find commits whose messages indicate a security fix. The code *before* the commit is your vulnerable sample.

1.  **Identify Target Repositories:** Find large, popular Python projects (e.g., Django, Flask, Requests, Pillow, Ansible). Popular projects are more likely to have had security issues reported and fixed.
2.  **Search Commit Logs:** Programmatically search the commit history of these repos for keywords like:
    *   `"security"`, `"vulnerability"`, `"fix"`, `"CVE-"`, `"XSS"`, `"SQL injection"`, `"RCE"`, `"cross-site scripting"`, `"directory traversal"`.
3.  **Extract Code Changes:** For each matching commit, extract the "diff". The lines that were removed/changed (the "before" state) represent the **vulnerable code**. The lines that were added (the "after" state) can be considered a **patched/non-vulnerable** example.
4.  **Use a Tool:** Don't do this manually! Use a library like **PyDriller**. It's designed specifically for mining software repositories.

**Example Workflow with PyDriller:**

```python
from pydriller import Repository

# URL of a repo you want to mine
repo_url = 'https://github.com/django/django.git'
keywords = ['security', 'vulnerability', 'cve-', 'xss', 'sql injection']

# This will only check the last 500 commits for speed, remove for full search
commits = Repository(repo_url, only_in_branch='main', order='reverse').traverse_commits()

for commit in commits:
    # Check if any keyword is in the commit message (case-insensitive)
    if any(keyword in commit.msg.lower() for keyword in keywords):
        print(f"Potential Security Fix Found in Commit: {commit.hash}")
        print(f"Message: {commit.msg}\n")
        
        for modification in commit.modified_files:
            if modification.filename.endswith('.py'):
                print(f"--- File: {modification.filename} ---")
                # diff contains the unified diff format
                # source_code_before is the full file content before the change
                
                # You can parse the diff to get the exact vulnerable lines
                print("Vulnerable code might be in the 'removed' lines of this diff:")
                print(modification.diff)
                
                # You can store `modification.source_code_before` as the vulnerable sample
                # and `modification.source_code` as the patched sample.
                # NOTE: You'll need to be smart about extracting just the relevant function or block.
```

#### Method B: Using Static Analysis Tools as Oracles (Weak Supervision)

Use existing security scanners to generate labels for you. The labels won't be perfect (they'll have false positives), but it's a great way to bootstrap a dataset.

1.  **Choose a Tool:** Use a well-known Python static analysis security tool like **Bandit**.
2.  **Run it at Scale:** Run Bandit on your entire CodeSearchNet dataset (or a large subset).
3.  **Collect Findings:** Every time Bandit reports a vulnerability (e.g., `B307: use of insecure hash function`), extract that code snippet (the function or class where it occurred) and label it with the vulnerability type (e.g., `insecure-hash`).

**Example Workflow with Bandit:**
```bash
# 1. Install bandit
pip install bandit

# 2. Run bandit on a project and output to JSON
bandit -r /path/to/your/python_code/ -f json -o bandit_report.json

# 3. Write a Python script to parse the report
import json

with open('bandit_report.json', 'r') as f:
    report = json.load(f)

for result in report['results']:
    filename = result['filename']
    line_number = result['line_number']
    vulnerability_type = result['test_id'] # e.g., 'B101'
    code_snippet = result['code']
    
    print(f"Vulnerability '{vulnerability_type}' found in {filename} at line {line_number}")
    print(f"Code: {code_snippet}")
    # Now, you can programmatically extract the function containing this line
    # from the original file and save it as a labeled sample.
```

### Data Labeling and Structuring

Once you have your code snippets, you need to decide on your labeling scheme.

*   **Granularity:** Are you labeling entire files, functions, or lines? **Labeling at the function level is the most common and effective approach.**
*   **Label Format:**
    *   **Binary:** `1` (vulnerable) vs. `0` (non-vulnerable). This is the simplest. Your CodeSearchNet data can serve as your "0" class, and the samples you just collected are your "1" class.
    *   **Multi-class:** `CWE-79` (XSS), `CWE-89` (SQLi), `CWE-78` (Command Injection), `SAFE`. This is more powerful but requires more precise labeling, which you can often get from commit messages or Bandit reports.

### Final Recommended Workflow

1.  **Negative Samples (Class 0):** Use your existing CodeSearchNet dataset. For each file, extract all the functions. These are your `non-vulnerable` samples.
2.  **Positive Samples (Class 1):** Use **Method A (Git Mining)** with PyDriller as your primary method. It finds real, confirmed vulnerabilities.
3.  **Supplement Positive Samples:** Use **Method B (Bandit)** to find more "common mistake" types of vulnerabilities and to increase the size of your dataset.
4.  **Define Granularity:** Decide to work at the **function level**. For every vulnerable line you find, extract the entire function that contains it.
5.  **Create Your Final Dataset:** Structure your data, for example, in a CSV or JSON file:
    ```json
    [
      {
        "code": "def get_user(request):\n  user_id = request.GET.get('id')\n  return db.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "label": 1,
        "cwe": "CWE-89" 
      },
      {
        "code": "def calculate_sum(a, b):\n  return a + b",
        "label": 0,
        "cwe": "SAFE"
      }
    ]
    ```

This hybrid approach will give you a robust, large-scale, and relevant dataset to train a powerful deep learning model. Good luck