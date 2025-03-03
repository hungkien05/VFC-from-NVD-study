import json
import re,os
import time
import requests
from lib import check_if_commit_exist, create_file_if_not_exists, load_jsonl

# Placeholder for your GitLab API token
gitlab_api_token = ""
headers = {"Authorization": f"Bearer {gitlab_api_token}"}
GL_ISSUE_PULL = re.compile(r"http(s?)://gitlab.com/([0-9a-z/]+)(/-)?/(issues|merge_requests)/([0-9]+)\S*\s*")
GL_COMMIT = re.compile(r"http(s?)://gitlab.com/([0-9a-z/]+)(/-)?/(commit)/([0-9a-f]{5,40})\S*\s*")
OUTPUT_LOG_DIR = "update/"
output_dir =""

# Function to load CVE data from the JSON file
def load_cve_data(filepath):
    cve_data = []
    if filepath.endswith(".json"):
        with open(filepath, 'r') as file:
            cve_data= json.load(file)
    elif filepath.endswith(".jsonl"):
        cve_data = load_jsonl(filepath)
    return cve_data
    
def handle_issue(project_id, issue_id, count):
    project_id = project_id.replace("/","%2F")
    url = f"https://gitlab.com/api/v4/projects/{project_id}/issues/{issue_id}/closed_by"
    if count >3:
        print(f"Cannot GET {url}")
        return []
    response = requests.get(url, headers=headers)
    if response.status_code ==200:
        print(f"Success API {url}")
        data = response.json()
    else:
        print(f"Error API {url}: {response.content}")
        time.sleep(10)
        handle_issue(project_id, issue_id, count +1) # try again
    sha_list = []
    for merge_rq in data:
        sha_list.append(merge_rq["sha"])
    return sha_list

def handle_merge_rq(project_id, merge_id, count):
    project_id = project_id.replace("/","%2F")
    url = f"https://gitlab.com/api/v4/projects/{project_id}/merge_requests/{merge_id}/commits"
    if count >3:
        print(f"Cannot GET {url}")
        return []
    response = requests.get(url, headers=headers)
    if response.status_code ==200:
        print(f"Success API {url}")
        data = response.json()
    else:
        print(f"Error merge rq API {url}: {response.content}")
        time.sleep(10)
        handle_merge_rq(project_id, merge_id, count +1) # try again
    sha_list = []
    for commit in data:
        sha_list.append(commit["id"])
    return sha_list


# Function to classify and resolve commit SHAs
def resolve_commit_shas(ref_urls):
    commit_shas = []
    project_ids = []
    
    for url in ref_urls:
        # Determine if the URL is for an issue or a merge request
        issue_merge_re = GL_ISSUE_PULL.match(url)
        commit_re = GL_COMMIT.match(url)
        if issue_merge_re:
            project_id = issue_merge_re.group(2)
            issue_merge_id = issue_merge_re.group(5)
            project_ids.append(project_id)
            if "/-/issues/" in url:
                commit_shas += handle_issue(project_id, issue_merge_id, 0)
            elif "/-/merge_requests/" in url:
                commit_shas += handle_merge_rq(project_id, issue_merge_id, 0)
        
        if commit_re:
            project_id = commit_re.group(2)
            project_ids.append(project_id)
            commit_sha = commit_re.group(5)
            commit_shas.append(commit_sha)
    return project_ids,commit_shas

# Function to download and save patch files
def download_and_save_patch_files(cve_data):
    for item in cve_data:
        cve_id = item['cve_id']
        ref_urls = item['patch_url']
        project_ids,commit_shas = resolve_commit_shas(ref_urls)
        for project_id, sha in zip(project_ids,commit_shas):
            commit_filename = f'{cve_id}.{project_id.replace("/",".")}.{sha}.txt'
            is_exist = check_if_commit_exist(commit_filename, "gitlab")
            file_path = f"{output_dir}/{commit_filename}"
            if os.path.exists(file_path) or is_exist:
                continue
            patch_url = f"https://gitlab.com/{project_id}/-/commit/{sha}.patch"
            response = requests.get(patch_url)
            if response.status_code == 200:
                log_filepath = output_dir + "/log.txt"
                with open(log_filepath, "a") as f:
                    f.write(f"{cve_id}\tgitlab\t{project_id}\t{sha}\n")
                with open(file_path, 'w') as file:
                    file.write(response.text)

def crawl_commit(filepath, passed_output_dir):
    # filepath = 'nvd_cve_patch_gitlab.json'  # Adjust the file path
    global output_dir
    output_dir = passed_output_dir +"/gitlab/commit"
    os.makedirs(output_dir, exist_ok=True)
    create_file_if_not_exists(output_dir+"/log.txt")
        
    cve_data = load_cve_data(filepath)
    
    download_and_save_patch_files(cve_data)
# Main execution
if __name__ == "__main__":
    crawl_commit(filepath)
