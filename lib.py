import json
import os
import re
import signal
import sys
import time

import config
from datetime import datetime,timezone
from dateutil import parser
from datetime import datetime
from dateutil.relativedelta import relativedelta


import requests
import time
from datetime import datetime
from itertools import cycle
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
# from platform_api_caller import BitBucket_API_Caller, GitHub_API_Caller, GitLab_API_Caller

class DatabaseConnection:
#   __instance = None
  
  def __init__(self, database_path) -> None:
      self.database_path = database_path
      self.instance = None

#   @staticmethod
  def get_instance(self):
    if self.instance is None:
      # Replace with your actual connection logic (host, username, password, etc.)
      self.instance = sqlite3.connect(self.database_path)
    return self.instance

  def close_connection(self):
    if self.instance:
      self.instance.close()
      self.instance = None


def output_json(output_path, output_data,):
    with open(output_path, "w") as f:
        json.dump(output_data,f, indent=4)
    print(f"Json dumped to {output_path}")
    return

datetime_commit_dict = dict()
def create_file_if_not_exists(filename):
    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            pass  # This is a no-op, just creating an empty file
            

def load_jsonl(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            # Parse each line as a JSON object
            data.append(json.loads(line.strip()))
    return data

def load_json(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data
def dump_jsonl(data, filename):
    create_file_if_not_exists(filename)
    with open(filename, 'a') as f:
        for item in data:
            json.dump(item, f)
            f.write('\n')
# def get_base_save_dir():
#     return "update"

def check_if_commit_exist(commit_filename, platform):#if not, add it the log of existing
    base_save_dir = config.BASE_METADATA_DIR
    return False # comment to  restore to normal monitor
    year = commit_filename.split("-")[1]
    create_file_if_not_exists(f"{base_save_dir}/existing/{platform}/{year}.txt")
    with open(f"{base_save_dir}/existing/{platform}/{year}.txt", "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.strip() == commit_filename:
            return True
    with open(f"{base_save_dir}/existing/{platform}/{year}.txt", "a") as f:
        f.write(commit_filename+"\n")
    return False

def convert_datetime_to_UTC(datetime_str): #convert any datetime string to UTC timezone string in format %Y-%m-%dT%H:%M:%SZ
    date = parser.parse(datetime_str)
    date = date.astimezone(timezone.utc)
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')

def contains_full_range(arr, start_num, end_num):
    # Create a set of all numbers in the range from a to b, inclusively
    # required_numbers = set(range(start_num, end_num + 1))
    required_numbers = set(range(start_num, end_num ))
    # Convert the input array to a set to remove duplicates and allow for efficient lookup
    arr_set = set(arr)
    # Check if the array set contains all the required numbers by comparing difference
    return required_numbers.issubset(arr_set)

# def get_commit_datetime(commit_url,repo):
#     global datetime_commit_dict
#     if commit_url in datetime_commit_dict:
#         date = datetime_commit_dict[commit_url]
#     else:
#         commit = commit_url.split("/")[-1]
#         if  "github" in commit_url:
#             platform_api_caller = GitHub_API_Caller(repo, commit)
#         elif "gitlab" in commit_url:
#             platform_api_caller = GitLab_API_Caller(repo, commit)
#         elif "bitbucket" in commit_url:
#             platform_api_caller = BitBucket_API_Caller(repo, commit)
#         date = platform_api_caller.get_commit_datetime(0)
#         datetime_commit_dict[commit_url] = date
#     return date
    
def find_start_end_lines_of_substring(whole_string, substring):
    index = whole_string.find(substring)
    if index != -1:
        # Count the number of lines before the substring
        lines_before = whole_string[:index].count('\n') + 1  # +1 because line count starts at 1
        
        # Count the number of lines in the substring
        substring_line_count = substring.count('\n') + 1
        
        # Calculate the start and end line numbers
        start_line = lines_before
        end_line = lines_before + substring_line_count - 1
        
        # print(f"The substring starts at line {start_line} and ends at line {end_line}.")
        return start_line, end_line
    else:
        # print("The substring was not found in the whole string.")
        return None, None

def get_year_from_cve(cve_id):
    return cve_id.split('-')[1]



def get_cwe_by_cve(cve_id, data = None):
    # print(f"Start {cve_id}")
    all_cve_api_file = config.CVE_API_PATH
    # all_cve_api_file = "nvd_cve_all_api/nvd_cve_120.json"
    
    # year = get_year_from_cve(cve_id)
    # cve_api_file = f"nvd_cve_all_api/year/cve_{year}.json"
    cwe_ids = []
    if data == None:
        with open(all_cve_api_file, "r") as f:
            data = json.load(f)
    for cve in data["vulnerabilities"]:
        if cve["cve"]['id'] == cve_id:
            try:
                weaknesses = cve["cve"]["weaknesses"]
            except Exception as e: #cve does not have cwe information yet
                break
            for weakness in weaknesses:
                for cwe in weakness["description"]:
                    cwe_ids.append(cwe["value"])
            # print(f"Done")
            break
    return list(set(cwe_ids))

def get_cwe_by_cve_json(cve_data):
    cwe_ids = []
    try:
        weaknesses = cve_data["weaknesses"]
    except Exception as e: #cve does not have cwe information yet
        return cwe_ids
    for weakness in weaknesses:
        for cwe in weakness["description"]:
            cwe_ids.append(cwe["value"])
    return cwe_ids
        

def find_files_keyword_in_dir(directory, keyword):
    found_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            try:
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8') as f:
                    if keyword in f.read():
                        return True
                        found_files.append(path)
            except Exception as e:
                print(f"Failed to read {path}: {str(e)}")
    return False
    # return found_files
    
def check_if_keyword_exist_in_file(filepath, keyword):
    with open(filepath, "r") as f:
        content = f.read()
    if keyword in content:
        return True
    return False

