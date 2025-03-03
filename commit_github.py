from functools import partial
import json
from os import execlp, removedirs
import signal
import sys
import urllib.request
from lib import DatabaseConnection, calculate_2month_period, check_if_commit_exist, check_if_keyword_exist_in_file, exit_search_git_repo, get_cwe_by_cve_json, get_keyword_by_cwe, get_repo_by_cpe_product_name, load_jsonl, make_exit_handler, output_json

import re
import time
import os
import traceback
import requests
from requests_oauth2 import OAuth2BearerToken
from platform_api_caller import GitHub_API_Caller

from lib import create_file_if_not_exists, find_files_keyword_in_dir
from config import NVD_API_DATA_PATH, GITHUB_VFC_DIR

GLOBAL_REQUEST_COUNT = 0
GLOBAL_DOWNLOAD_COUNT = 0

OUTPUT_LOG_DIR = "update/"
output_dir = "crawled_patch/v-szz/vic/"
output_commit_dir = None

MAX_TRY_TIME = 6
GH_TOKEN = []  # NOTE put your own github token here

# repo platform registry
repo_platform = "github"
GH_REST_URL = 'https://api.github.com/repos'
if repo_platform == "github":
    GH_ISSUE_PULL = re.compile(r"http(s?)://github.com/([^/]+/[^/]+)/(issues|pull)/([0-9]+)\S*\s*")
    GH_COMMIT = re.compile(r"http(s?)://github.com/([^/]+/[^/]+)/(commit|pull/[0-9]+/commits)/([0-9a-f]{5,40})\S*\s*")
else:
    GH_ISSUE_PULL = re.compile(r"http(s?)://gitlab.com/([^/]+/[^/]+)(/-)?/(issues|pull)/([0-9]+)\S*\s*")
    GH_COMMIT = re.compile(r"http(s?)://gitlab.com/([^/]+/[^/]+)(/-)?/(commit|pull/[0-9]+/commits)/([0-9a-f]{5,40})\S*\s*")



def collect_nvd_github_patch():
    directory_path = f"nvd_cve_all/"
    patch_data = list()
    count_gh_commit = 0
    cve_with_patch = 0
    total_cve = 0
    for f in os.listdir(directory_path):
        file_path = directory_path + f
        data = json.load(open(file_path, 'r', encoding="utf-8"))
        for vuln in data["CVE_Items"]:
            total_cve += 1
            cve_id = vuln["cve"]["CVE_data_meta"]["ID"]
            patch_url = list()
            for reference in vuln["cve"]["references"]["reference_data"]:
                link = f"{repo_platform}.com"
                if repo_platform == "bitbucket":
                    link = f"bitbucket.org"
                if "Patch"  in reference["tags"] and link in reference["url"]:
                    # NOTE 也可以使用正则表达式来匹配
                    patch_url.append(reference["url"])
                    if "commit" in reference["url"]:
                        count_gh_commit += 1

            if len(patch_url) > 0:
                patch_data.append({"cve_id": cve_id, "patch_url": patch_url})
    
    with open(f"nvd_cve_nopatch_{repo_platform}.json", "w") as f:
        json.dump(patch_data, f, indent=4)
    

def get_by_oauth2(url):
    # 获取get请求
    # request的逻辑都封装在这个函数中：休眠和TOKEN替换
    t = 1
    while t < MAX_TRY_TIME: 
        try:
            with requests.Session() as s:
                global GLOBAL_REQUEST_COUNT
                if (GLOBAL_REQUEST_COUNT % 1000) == 0:
                    time.sleep(1)
                s.auth = OAuth2BearerToken(GH_TOKEN[int(GLOBAL_REQUEST_COUNT / 4900)])  # GitHub不使用验证，很容易rate limit exceeded
                GLOBAL_REQUEST_COUNT += 1
                r = s.get(url)
                r.raise_for_status()
            
            return r.json()
        except Exception as e:
            print("[ERROR]", url)
            print(e)
            # print(traceback.print_exc())  # 更详细的报错信息
            time.sleep(1)
            t += 1
    
    return None

def write_commit(file_path, cve_id, repo, commit_id,diff):
    global output_dir, output_commit_dir
    log_filepath = os.path.dirname(output_dir) + "/log.txt" #change this
    os.makedirs(output_dir, exist_ok=True)
    create_file_if_not_exists(log_filepath)
    with open(log_filepath, "a") as f: 
        f.write(f"{cve_id}\tgithub\t{repo}\t{commit_id}\n")
    with open(file_path, 'w') as f:
        f.writelines(diff)
    


def download_diff(url):
    # 爬取diff
    # https://api.github.com/repos/squid-cache/squid/git/commits/1c9593caa2138e6764143fde832e21ab969c735e
    t = 1
    print("Going to download_diff")
    while t < MAX_TRY_TIME:
        try:
            global GLOBAL_DOWNLOAD_COUNT
            if GLOBAL_DOWNLOAD_COUNT % 1000 == 0:
                time.sleep(1)
            GLOBAL_DOWNLOAD_COUNT += 1
            diff = urllib.request.urlopen(url)
            encoding = diff.headers.get_charsets()[0]
            diff = diff.read().decode(encoding)
            print(f"Complete: {url}")
            return diff
        except Exception as e:
            print("[ERROR]", url)
            print(e)
            # print(traceback.print_exc())  # 更详细的报错信息
            time.sleep(1)
            t += 1

    return None


def crawl_diff(filepath, passed_output_dir):
    # 爬取所有在CVE reference中的diff
    global output_dir
    output_dir = passed_output_dir+"/github/"
    if filepath.endswith(".json"):
        nvd_gh_patch = json.load(open(filepath, 'r'))
    elif filepath.endswith(".jsonl"):
        nvd_gh_patch = load_jsonl(filepath)
    missing_list = []
    with open("missing_cve.txt", "r") as f:
        lines = f.readlines()
    for line in lines:
        missing_list.append(line.strip())
    count = [0, 0]
    processed_url = list()
    sleep_count = 0
    processed_url_file = open("processed_url.txt", "w")
    for sample in nvd_gh_patch:
        if (sleep_count % 100) == 0:
            print(sleep_count)
            time.sleep(1)
            sleep_count += 1
        
        cve_id = sample["cve_id"]
        if cve_id != "CVE-2018-11758":
            continue
        # if cve_id not in missing_list:
        #     continue
        
        print(cve_id)
        for url in sample["patch_url"]:
            # if url != "https://github.com/proftpd/proftpd/issues/902":
            #     continue
            if url in processed_url:
                # 已经处理
                print("URL processed")
                processed_url_file.write(f"{cve_id}\n")
                continue
            processed_url.append(url)

            gh_commit = GH_COMMIT.match(url)
            gh_issue_pull = GH_ISSUE_PULL.match(url)
            # gh_blob = GH_BLOB.match(url)

            if gh_commit:
                # url是commit，一定只有一个commit，pull对应的commits是指定的
                repo = gh_commit.group(2)  # user/repo
                commit_id = gh_commit.group(4)
                
                # 更换repo中的/
                commit_filename = f"{cve_id}.{repo.replace('/', '.')}.{commit_id}.txt"
                is_exist = check_if_commit_exist(commit_filename, "github")
                file_path = f"{output_dir}/{commit_filename}"
                if os.path.exists(file_path) or is_exist:
                    # 已经爬取
                    continue

                diff = download_diff(f"https://github.com/{repo}/commit/{commit_id}.patch")
                if diff is not None:
                    write_commit(file_path, cve_id, repo, commit_id,diff)
                    count[0] += 1

            elif gh_issue_pull:
                # url是pull或issue都可能对应多个commit
                # pull
                # issue
                # https://gist.github.com/pietroalbini/0d293b24a44babbeb6187e06eebd4992
                repo = gh_issue_pull.group(2)
                id_ = gh_issue_pull.group(4)
                if gh_issue_pull.group(3) == "pull":
                    # pull一定有相应的commit
                    pull = get_by_oauth2(url=f"{GH_REST_URL}/{repo}/pulls/{id_}/commits")
                    if pull is not None:
                        for commit in pull:
                            # 一个pull request可能对应多个commit
                            commit_id = commit["sha"]
                            commit_filename = f"{cve_id}.{repo.replace('/', '.')}.{commit_id}.txt"
                            is_exist = check_if_commit_exist(commit_filename, "github")
                            file_path = f"{output_dir}/{commit_filename}"
                            if os.path.exists(file_path) or is_exist:
                                continue
                            diff = download_diff(f"https://github.com/{repo}/commit/{commit_id}.patch")
                            if diff is not None:
                                write_commit(file_path, cve_id, repo, commit_id,diff)
                                count[0] += 1
                else:
                    # issues从相关的timeline中找
                    issue_timeline = get_by_oauth2(url=f"{GH_REST_URL}/{repo}/issues/{id_}/timeline")
                    if issue_timeline is not None:
                        for act in issue_timeline:
                            # TODO 可以只选择timeline的最后一个commit
                            commit_id = act.get("commit_id")
                            if commit_id is not None:
                                # 部分item没有commit_id这个key
                                # 部分commit_id对应的value为空
                                commit_filename = f"{cve_id}.{repo.replace('/', '.')}.{commit_id}.txt"
                                is_exist = check_if_commit_exist(commit_filename, "github")
                                file_path = f"{output_dir}/{commit_filename}"
                                if os.path.exists(file_path) or is_exist:
                                    continue
                                diff = download_diff(f"https://github.com/{repo}/commit/{commit_id}.patch")
                                if diff is None:
                                    commit_url = act.get("commit_url").replace("https://api.","https://").replace("/repos/","/").replace("/commits/","/commit/")
                                    print(commit_url)
                                    gh_commit = GH_COMMIT.match(commit_url)
                                    repo = gh_commit.group(2)  # user/repo
                                    commit_id = gh_commit.group(4)
                                    commit_filename = f"{cve_id}.{repo.replace('/', '.')}.{commit_id}.txt"
                                    is_exist = check_if_commit_exist(commit_filename, "github")
                                    file_path = f"{output_dir}/{commit_filename}"
                                    if os.path.exists(file_path) or is_exist:
                                        continue
                                    diff = download_diff(f"https://github.com/{repo}/commit/{commit_id}.patch")
                                if diff is not None:
                                    write_commit(file_path, cve_id, repo, commit_id,diff)
                                    count[0] += 1
            
            else:
                count[1] += 1
                print(url)

    print(count)
    



# def search_keyword_in_repo(): 
#     live_output_path = "vfc/live_output.txt"
#     output_path ="vfc/git_repo_search.json"
#     cpe_connection = DatabaseConnection("side_data/titan_wp1b.db")
#    #todo: 1. Gitlab and bitbucket
#         # 2.          
#     cwe_dict = dict()
#     count =0
#     incompleted = []
#     no_repo = []
#     no_keyword_found = []
#     no_commit_found = []
#     total_vfc_list = []
#     create_file_if_not_exists(live_output_path)
#     fail_stats_str = ""
    
#     with open('nvd_cve_all_api/all.json', 'r') as f: 
#     # with open('sandbox/cve.json', 'r') as f:
#         data = json.load(f)
#     for cve in data["vulnerabilities"]:
#         # sigterm_handler = partial(exit_search_git_repo, output_func =output_json, output_path=output_path, output_data=total_vfc_list)
#         handler = make_exit_handler(output_func =output_json, output_path=output_path, output_data=total_vfc_list,output_custom_str=fail_stats_str )
#         signal.signal(signal.SIGINT, handler) #catch Ctrl+C (premature exit) and output json
        
#         count +=1
#         if count <40379:
#             continue
#         cve_id = cve["cve"]["id"]
#         print(f"{count}: {cve_id}") 
#         # if not find_files_keyword_in_dir(GITHUB_VFC_DIR, cve_id):
#         if check_if_keyword_exist_in_file("side_data/vfc_cve_id.txt", cve_id):
#             continue
#         if "configurations" not in cve["cve"]:
#             incompleted.append(cve_id)
#             continue
#         product_names = set()
#         for config in cve["cve"]["configurations"]:
#             if "nodes" not in config: # nvd cve not full information
#                 continue
#             for node in config["nodes"]:
#                 if "cpeMatch" not in node:
#                     incompleted.append(cve_id)
#                     continue
#                 for match in node["cpeMatch"]:
#                     if match["vulnerable"] != True:
#                         incompleted.append(cve_id)
#                         continue
#                     cpe = match["criteria"]
#                     try:
#                         product_names.add(cpe.split(":")[4])
#                     except Exception:
#                         incompleted.append(cve_id)
#                         print(f"Cannot split ':' for cpe_match: {cpe}")

#         repo_list = get_repo_by_cpe_product_name(product_names,cpe_connection.get_instance())
#         # print("Done found repo from cpe")
#         if len(repo_list) <1: # no git repo found
#             no_repo.append(cve_id)
#             continue  
#         pub_date = cve["cve"]["published"].split("T")[0]
#         period = calculate_2month_period(pub_date)
#         cwe_ids = get_cwe_by_cve_json(cve["cve"])
#         keywords = ["CVE", "security fix", "vulnerable", "vulnerability"]
#         for cwe_id in cwe_ids:
#             keywords = [*keywords, *get_keyword_by_cwe(cwe_id)]
#         keywords = list(set(keywords))
#         keywords = [cve_id,*keywords,]
#         if len(keywords) <1: # no keyword found from cwe_ids
#             no_keyword_found.append(cve_id)
#             continue
#         commits = []
#         keywords_origin = []
#         for repo in repo_list:
#             caller = GitHub_API_Caller(repo)
#             found_commits, keywords = caller.search_commit_by_keywords(keywords, period)
#             print(f" found vfc = {found_commits}")
#             commits = [*commits, *found_commits]
#             keywords_origin = [*keywords_origin, *keywords]
#         if len(commits) <1:
#             no_commit_found.append(cve_id)
#         else:
#             total_vfc_list.append({"cve_id": cve_id, "patch_url": commits, "origin": "Git repo search", "keyword": keywords_origin})
#             with open(live_output_path, "a") as f:
#                 f.write(cve_id+"\n")
#                 # f.writelines(commits)
#                 for keyword,commit in zip(keywords_origin,commits):
#                     f.write(f"{keyword}\t{commit}\n")
#                 f.write("-------------------\n")
                
#         fail_stats_str = f"\nincompleted_cve_count = {len(incompleted)}\nno_repo_count = {len(no_repo)}\nno_keyword_found_count = {len(no_keyword_found)}\nno_commit_found_count = {len(no_commit_found)}\n"
    
#     cpe_connection.close_connection()
#     error_info = {
#         "incomplete": incompleted,
#         "no_repo": no_repo,
#         # "no_keyword": no_keyword_found,
#         "no_commit_found": no_commit_found,
#     }
#     with open(output_path, "w") as f:
#         json.dump(total_vfc_list,f, indent=4)
#     with open("vfc/log_error_git_repo_search.json", "w") as f:
#         json.dump(error_info,f, indent=4)
    
    
if __name__ == "__main__":
    collect_nvd_github_patch()
    # search_keyword_in_repo()
    