import json
import re

def find_distinct_github_commit_links(file_path, chosen_cve_id):
    distinct_patch_urls = set()
    github_commit_pattern = re.compile(r'https://github\.com/.+?/commit/[0-9a-fA-F]{40}')

    # Open the JSONL file and read each line
    with open(file_path, 'r') as file:
        for line in file:
            item = json.loads(line.strip())
            if item['cve_id'] == chosen_cve_id:
                for url in item['patch_url']:
                    if github_commit_pattern.match(url):
                        distinct_patch_urls.add(url)
    
    # Check if we found any distinct GitHub commit links
    if distinct_patch_urls:
        for url in distinct_patch_urls:
            print(url)
    else:
        print("CVE ID not found or no GitHub commit links found for:", chosen_cve_id)

# Example usage
file_path = 'result/output_live.json'
chosen_cve_id = 'CVE-2022-28347'
find_distinct_github_commit_links(file_path, chosen_cve_id)
