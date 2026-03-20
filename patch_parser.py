import json
import os
import time
import requests
import config
from unidiff import PatchSet
from platform_api_caller import GitHub_API_Caller, GitLab_API_Caller, BitBucket_API_Caller
from code_parser import BaseParser, find_lang, get_origin
from lib import create_file_if_not_exists, get_cwe_by_cve
from config import *
from __init__ import cve_data


GH_TOKEN = ""
function_save_dir = ""

class Metadata_Retriever: #Get affected filenames and functions from vul-fixing commits 
    def __init__(self, patch_path):
        self.patch_path = patch_path
        with open(patch_path, "r") as f:
            self.lines = f.readlines()
        
    def get_filename(self):
        affected_files = []
        current_file = {"filename": None, "added_no": [], "removed_no": [], "changed_no":[]}
        
        try:
            with open(self.patch_path, 'r', encoding="utf-8") as patch_file:
                patch_set = PatchSet(patch_file)
        except Exception as e:
            return []
        for patched_file in patch_set:
            # print(f"File: {patched_file.path}")
            current_file["filename"] = patched_file.path
            # Iterate through hunks in the patched file
            for hunk in patched_file:
                added_lines = []
                removed_lines = []
                for line in hunk:
                    if line.is_added:
                        # print(f"    Added line {line.target_line_no}: {line.value.strip()}")
                        # current_file["added_no"].append(line.target_line_no)
                        added_lines.append(line.target_line_no)
                    elif line.is_removed:
                        # print(f"    Removed line {line.source_line_no}: {line.value.strip()}")
                        # current_file["removed_no"].append(line.source_line_no)
                        removed_lines.append(line.source_line_no)
                current_file["changed_no"].append((removed_lines, added_lines))
            affected_files.append(current_file)
            current_file = {"filename": None, "added_no": [], "removed_no": [], "changed_no":[]}
        #an example of current_file would be: 
        #   {"filename": "a.java", "added_no": [], "removed_no": [], "changed_no":[ ([1,2], [3,4]), ([5], [6,7,8]) ]}
        for file in affected_files:
            if file["filename"] == "src/test/java/com/rebuild/core/support/task/QuickCodeReindexTaskTest.java":
                print(f"added = {file['added_no']}")
                print(file["removed_no"])
        return affected_files
class Files_Retriever:
    def __init__(self, patch_path, affected_files, platform):
        parts = os.path.basename(patch_path).split(".")
        self.repo = f"{parts[1]}.{parts[2]}".replace(".","/")
        self.fix_commit = parts[3]
        self.cve_id = parts[0]
        print(self.cve_id)
        self.affected_files = affected_files
        self.count_call_api = 0
        
        
        if platform == "github":
            self.platform_api_caller = GitHub_API_Caller(self.repo, self.fix_commit)
        elif platform == "gitlab":
            self.platform_api_caller = GitLab_API_Caller(self.repo, self.fix_commit)
        elif platform == "bitbucket":
            self.platform_api_caller = BitBucket_API_Caller(self.repo, self.fix_commit)
        else:
            raise Exception(f"Invalid Git platform name: {platform}")
        self.parent_commit = self.platform_api_caller.get_parent_commit()
        
        # if self.count_call_api >2:
        #     self.count_call_api = 0
        #     return None
        # headers = {
        #         'Authorization': f'Bearer {GH_TOKEN}',
        #         'Accept': 'application/vnd.github.v3+json',
        #     }
        # data =None
        # api_url = f"https://api.github.com/repos/{self.repo}/commits/{self.fix_commit}"
        # response = requests.get(api_url, headers=headers)
        # if response.status_code ==200:
        #     data = response.json()
        # else:
        #     print(f"Error getting parent commit {api_url}: {response.content}")
        #     self.count_call_api +=1
        #     time.sleep(5)
        #     return self.get_parent_commit()
        
        # try:
        #     self.parent_commit = data["parents"][0]["sha"]
        # except Exception as e:
        #     return None
        # print(self.parent_commit)
        # return self.parent_commit
    
    def get_function(self):
        global function_save_dir
        count_func = 0
        save_path = f"{function_save_dir}/{self.cve_id}.json"
        try:
            file = open(save_path, 'r')
            data = json.load(file)
            file.close()
        except Exception as e:
            data = []
        current_log_detail = None
        for file in self.affected_files:
            file_path = file["filename"]
            parser = find_lang(file_path)
            if parser == None:
                continue
            changed_lines_no = file["changed_no"]
            #start request API
            parent_file_content = self.platform_api_caller.get_file_content( self.parent_commit, file_path) #only get fix vul
            fixed_file_content = self.platform_api_caller.get_file_content( self.fix_commit, file_path)
            
            if parent_file_content != None and fixed_file_content != None:
                functions = parser.get_functions(parent_file_content,fixed_file_content, changed_lines_no)
                count_func += len(functions)
                for function in functions:
                    vul_label = function[1] %2
                    commit_msg = None
                    if vul_label==1:
                        commit_msg = self.platform_api_caller.get_commit_message(self.parent_commit)
                    else:
                        commit_msg = self.platform_api_caller.get_commit_message(self.fix_commit)
                    origin = get_origin(function[1])
                    fix_commit_url = self.platform_api_caller.get_commit_url()
                    fix_commit_sha = fix_commit_url.split("/")[-1]
                    filename = os.path.basename(file_path).split(".")[0]
                    new_data = { 
                                "repo": self.repo, "parent_commit_sha":self.parent_commit, 
                                "commit_URL": fix_commit_url, "lang": parser.lang,
                                "vulnerable": vul_label, "file": file_path, "function": function[0],
                                "commit_message": commit_msg,
                                "origin":origin, 
                                "date": self.platform_api_caller.date,
                                "cve_id":self.cve_id, "cwe_id": get_cwe_by_cve(self.cve_id, cve_data),
                                "map_id": f"{function[2]}",
                                }
                    log_detail = f"{self.cve_id}, {parser.lang}, {self.platform_api_caller.get_commit_url()}"
                    if current_log_detail != log_detail:
                        with open(f"{function_save_dir}/log.txt", "a") as f:
                            f.write(f"{current_log_detail}\n")
                        current_log_detail = log_detail
                    data.append(new_data)
        with open(f"{function_save_dir}/log.csv", "a") as f:
            f.write(f"{current_log_detail}\n")
        if len(data) ==0:
            return 0
        with open(save_path, 'a') as file:
            json.dump(data, file, indent=4)
        return count_func
    
    # def get_fixed_function(self):
    #     global function_save_dir
    #     count_func = 0
    #     save_path = f"{function_save_dir}/{self.cve_id}.json"
    #     try:
    #         with open(save_path, 'r') as file:
    #             data = json.load(file)
    #     except FileNotFoundError:
    #         data = []
    #     current_log_detail = None
    #     for file in self.affected_files:
                            
            
    #         if parser == None:
    #             continue
    #         changed_lines_no = set(file["added_no"]+file["removed_no"])
    #         #start request API
    #         file_content = self.platform_api_caller.get_file_content( self.parent_commit, file_path) #only get fix vul
    #         if file_content != None:
    #             functions, lang = parser.get_functions(file_content, changed_lines_no)
    #             count_func += len(functions)
    #             for function in functions:
    #                 vul_label = function[1] %2
    #                 origin = get_origin(function[1])
    #                 new_data = {"repo": self.repo, "parent_commit_sha":self.parent_commit, 
    #                             "commit_URL": self.platform_api_caller.get_commit_url(), "lang": lang,
    #                             "vulnerable": vul_label, "file": file_path, "function": function[0],
    #                             "origin": origin,
    #                             }
    #                 log_detail = f"{self.cve_id}, {lang}, {self.platform_api_caller.get_commit_url()}"
    #                 if current_log_detail != log_detail:
    #                     with open(f"{function_save_dir}/log.txt", "a") as f:
    #                         f.write(f"{current_log_detail}\n")
    #                     current_log_detail = log_detail
    #                 data.append(new_data)
    #     with open(f"{function_save_dir}/log.csv", "a") as f:
    #         f.write(f"{current_log_detail}\n")
    #     if len(data) ==0:
    #         return 0
    #     with open(save_path, 'w') as file:
    #         json.dump(data, file, indent=4)
    #     return count_func
        
def process_function(patch_path, platform, passed_function_save_dir):
    global function_save_dir
    function_save_dir = passed_function_save_dir
    create_file_if_not_exists(f"{function_save_dir}/log_function.csv")
    retriever = Metadata_Retriever(patch_path)
    affected_files = retriever.get_filename()
    if len(affected_files) ==0:
        return 0
    file_retriever = Files_Retriever(patch_path, affected_files, platform)
    # file_retriever.get_parent_commit()
    if file_retriever.parent_commit == None:
        return 0
    return file_retriever.get_function()
    
if __name__ == "__main__":
    patch_path = "crawled_patch/github/CVE-2023-1495.getrebuild.rebuild.c9474f84e5f376dd2ade2078e3039961a9425da7.txt"
    patch_path = "crawled_patch/github/CVE-2013-5576.joomla.joomla-cms.fa5645208eefd70f521cd2e4d53d5378622133d8.txt"
    retriever = Metadata_Retriever(patch_path)
    affected_files = retriever.get_filename()
    file_retriever = Files_Retriever(patch_path, affected_files)
    file_retriever.get_parent_commit()
    file_retriever.get_function()
    