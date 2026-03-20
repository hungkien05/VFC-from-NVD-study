import hashlib
import json
import os
import re
import signal
import sys
import time

import certifi
import pandas as pd
import config
from datetime import datetime,timezone
from dateutil import parser
from datetime import datetime
from dateutil.relativedelta import relativedelta
import sqlite3


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
    year = commit_filename.split("-")[1]
    create_file_if_not_exists(f"{base_save_dir}/existing/{platform}/{year}.txt")
    with open(f"{base_save_dir}/existing/{platform}/{year}.txt", "r") as f:
        lines = f.readlines()
    for line in lines:
        if not config.IGNORE_EXISTING_VFC and line.strip() == commit_filename:
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

def get_desc_by_cve(cve_id,cve_data=None):
    #cve_data is config.CVE_API_PATH
    all_cve_api_file = config.CVE_API_PATH
    # all_cve_api_file = "nvd_cve_all_api/nvd_cve_120.json"
    
    # year = get_year_from_cve(cve_id)
    # cve_api_file = f"nvd_cve_all_api/year/cve_{year}.json"
    cwe_ids = []
    if cve_data == None:
        with open(all_cve_api_file, "r") as f:
            cve_data = json.load(f)
    for cve in cve_data["vulnerabilities"]:
        if cve["cve"]['id'] == cve_id:
            try:
                descriptions = cve["descriptions"]
                for desc in descriptions:
                    if desc["lang"] == "en":
                        return desc["value"]
            except Exception as e: #no desc in this cve_id
                return None
    return None
        

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

def calculate_2month_period(base_date):
    base_date = datetime.strptime(base_date, '%Y-%m-%d')
    date_month_before = base_date - relativedelta(months=1)
    date_month_after = base_date + relativedelta(months=1)
    return f"{date_month_before.strftime('%Y-%m-%d')}..{date_month_after.strftime('%Y-%m-%d')}"

def get_custom_datetime_period(base_date, delta_before, delta_after):
    base_date = datetime.strptime(base_date, '%Y-%m-%d')
    # date_month_before = base_date - relativedelta(months=1)
    date_month_before = base_date - relativedelta(days=delta_before)
    date_month_after = base_date + relativedelta(days=delta_after)
    return f"{date_month_before.strftime('%Y-%m-%d')}..{date_month_after.strftime('%Y-%m-%d')}"

def lcs_length(s1, s2):
    len1, len2 = len(s1), len(s2)
    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    return dp[len1][len2]

def get_repo_by_cpe_product_name(names, db_connection): #todo: categorize by git platform. Current only github
    repos = set()
    cpe_repo_filepath = "side_data/cpe_data.json"
    # pre_check = False
    # for name in names:
    #     if check_if_keyword_exist_in_file(cpe_repo_filepath, name):
    #         pre_check = True
    #         break
    # if not pre_check: 
    #     return []
    
    # with open("side_data/cpe_data.json", "r") as f:
    #     data = json.load(f)
    # for name in names:
    #     for entry in data:
    #         if entry["product"] == name:
    #             for repo_name in entry["repo_names"]:
    #                 repos.add(repo_name)
    
    #query sqlite3
    cursor_obj = db_connection.cursor() 
    for name in names:
        statement = f'''SELECT repo_names FROM cpe where product = "{name}"'''
        try: 
            cursor_obj.execute(statement) 
        except Exception as e:
            print('SQL select error: {}'.format(e))
        output = cursor_obj.fetchall() 
        for row in output: 
            repo_str = row[0]
            if repo_str != "[]":
                current_repo_list  = eval(repo_str) 
                if len(current_repo_list) >0:
                    for repo_name in current_repo_list:
                        #check if repo name and product name are actually related 
                        plain_repo_name = repo_name.split("/")[1]
                        lcs_len = lcs_length(plain_repo_name, name)
                        if (lcs_len/len(plain_repo_name) >0.4) or (lcs_len/len(name)>0.4):
                            repos.add(repo_name)
    # db_connection.commit()                 
    return list(repos)

def check_git_repo_exists(url):
    try:
        # Send a HEAD request to check if the repository exists
        response = requests.head(url)
        
        # If the status code is 200, the repository exists
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            # Handle other status codes
            print(f"Received status code {response.status_code}")
            return False

    except requests.ConnectionError:
        print("Failed to connect to the repository.")
        return False

def get_keyword_by_cwe(cwe_id):
    if "NVD-CWE" in cwe_id: #NVD-CWE-Other or NVD-CWE-noinfo
        return []
    id = int(cwe_id.split("-")[1])
    df = pd.read_csv("side_data/cwe_keywords.csv")
    csv_keywords_df = df.loc[df['ID'] == id, 'Keywords']
    csv_keywords = ""
    if csv_keywords_df.empty: #CWE not exist in the database
        return []
        
    if not pd.isna(csv_keywords_df).values.item():
        csv_keywords = csv_keywords_df.values.item()
    
    alternate_terms_df = df.loc[df['ID'] == id, 'Alternate Terms']
    alternate_terms = ""
    if not pd.isna(alternate_terms_df).values.item():
        alternate_terms =alternate_terms_df.values.item()
    if len(csv_keywords)+len(alternate_terms) <1:
        return []
    elif len(alternate_terms) <1:
        keywords = csv_keywords.lower()
    elif len(csv_keywords) <1:
        keywords = alternate_terms.lower()
    else:
        keywords = csv_keywords.lower() + "," + alternate_terms.lower()
    keywords = keywords.split(",")
    keywords = [word.strip() for word in keywords if word.strip()]
    return keywords

def exit_search_git_repo(signum, frame,output_func,output_path, output_data):
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, original_sigint)
    try:
        if input("\nReally quit? (y/n)> ").lower().startswith('y'):
            print("\nOutputing and quitting")
            output_func(output_path, output_data,)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nOk ok, outputing and quitting")
        output_func(output_path, output_data,)
        sys.exit(1)
    # restore the exit gracefully handler here    
    signal.signal(signal.SIGINT, exit_search_git_repo)
    
def make_exit_handler( output_func,output_path, output_data, output_custom_str = None):
    def signal_handler(signum, frame):
        try:
            if output_custom_str != None:
                custom_path ="vfc/fail_stats.txt"
                create_file_if_not_exists(custom_path)
                with open(custom_path, "a") as f:
                    f.write(output_custom_str)
            if input("\nReally quit? (y/n)> ").lower().startswith('y'):
                output_func(output_path, output_data,)
                sys.exit(1)
        except KeyboardInterrupt:
            print("\nOk ok, outputing and quitting")
            output_func(output_path, output_data,)
            sys.exit(1)
        sys.exit(1)
        
    return signal_handler

def handle_github_rate_limit(response):
    if response.status_code == 403 and 'rate limit exceeded' in response.text.lower():
        # Extract rate limit info
        rate_limit_reset = int(response.headers.get('X-RateLimit-Reset'))
        current_time = int(time.time())
        sleep_duration = rate_limit_reset - current_time
        
        reset_time = datetime.utcfromtimestamp(rate_limit_reset).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Rate limit exceeded. Sleeping until {reset_time} UTC ({sleep_duration} seconds)")

        # Sleep till the rate limit resets
        time.sleep(sleep_duration + 10)  # Adding extra 10 seconds to ensure the reset has fully occurred
        return True
    else:
        return False

def escape_java_quotes(text):
  """Escapes all quotes (both single and double) within a string using a regular expression.

  Args:
      text (str): The string to escape quotes in.

  Returns:
      str: The string with all quotes escaped.
  """
  return re.sub(r'"|', r'\1', text)  # Escape both single and double quotes

# List of GitHub API keys

round_robin_count = 0
def make_github_api_request(url, params, api_keys=None): #only for github
    global round_robin_count
    if api_keys == None:
        api_keys = config.GITHUB_API_KEYS
    keys = cycle(api_keys)  # Create an infinite iterator to cycle through API keys
    reset_times = []
    response = None
    fail_count = 0
    round_robin_count +=1
    if round_robin_count >= len(api_keys):
        round_robin_count = 0
    local_round_robin_count = 0
    for key in keys:
        if local_round_robin_count < round_robin_count: # alternately choose api round robin
            local_round_robin_count +=1
            continue
        headers = {
            'Authorization': f'Bearer {key}',
            'Accept': 'application/vnd.github.v3+json'
        }
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504 ])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, params=params, headers=headers, verify=certifi.where())
        
        if response.status_code == 200:
            return response  # Return the successful response
        elif response.status_code == 403 and 'rate limit exceeded' in response.text.lower():
            # Collect the rate limit reset time from the response headers

            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            reset_times.append(reset_time)
            print(f"Rate limit exceeded for key: {key}. Resets at {datetime.utcfromtimestamp(reset_time).strftime('%Y-%m-%d %H:%M:%S')} UTC")
            if len(reset_times) < len(api_keys):
                continue  # Check if there are other keys to try
            else:
                # Calculate the sleep duration: time until the earliest key reset
                min_reset_time = min(reset_times)
                sleep_duration = max(min_reset_time - int(time.time()), 0)
                print(f"All keys are rate limited. Sleeping for {sleep_duration} seconds.")
                time.sleep(sleep_duration + 10)  # Sleep until the reset time plus a buffer
                
                return make_github_api_request(url,params, api_keys)  # Recursive retry after waiting
        elif response.status_code == 500 or response.status_code == 503: #internal error from Github's end
            print(f"Error with key {key}: {response.status_code} {response.reason}")
            print(f"Error in lib.make_github_api_request() = {url}")
            time.sleep(30)
            continue # Try the next key or handle other errors
        else:
            print(f"Error with key {key}: {response.status_code} {response.reason}")
            print(f"Error in lib.make_github_api_request() = {url}")
            if response.status_code == 422:
                return response
            fail_count +=1
            if fail_count >= len(api_keys)*1.5: # exceeded threshold, skip this request
                fail_count = 0
                print(f"Skipping request {url}")
                return response
            print("Trying again with other keys...")
            continue  # Try the next key or handle other errors
    return response

    
    
directory_path = 'functions/062023_cutoff/github'
output_path = 'functions/combined_cutoff_062023_original.json'  # Path for the output file

# Helper function to calculate MD5 hash
def calculate_md5(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def remove_duplicate_func_from_dir(input_path, output_path= None, lang = None):
# Track seen hashes to identify duplicates
    seen_hashes = set()
    combined_data = []
    count =0
    # Iterate through each file in the directory
    for platform in ["github", 
                    #  "bitbucket", "gitlab"
                     ]:
        full_input_path = input_path +"/"+platform
        print(full_input_path)
        for filename in os.listdir(full_input_path):
            file_path = os.path.join(full_input_path, filename)
            print(file_path)
            if os.path.isfile(file_path) and filename.endswith('.json'):
                with open(file_path, 'r') as file:
                    data = json.load(file)
                    for item in data:
                        count +=1
                        function_text = item.get("function", "")
                        if lang != None and item["lang"] != lang:
                            continue
                        hash_val = calculate_md5(function_text)
                        if hash_val not in seen_hashes:
                            # If hash hasn't been seen, mark it as seen
                            seen_hashes.add(hash_val)
                            # Add the filename field to the item
                            item["cve_id"] = filename.split(".")[0]
                            # Add the item to the combined data
                            combined_data.append(item)

    if output_path != None:
        # Save the combined data to the output file
        with open(output_path, 'w') as file:
            json.dump(combined_data, file, indent=4)

    print(f"Combined JSON data saved to {output_path}.")   
    return combined_data


if __name__ == "__main__":
    # print(get_keyword_by_cwe("CWE-840"))
    # print(check_if_keyword_exist_in_file("side_data/vfc_cve_id.txt", "CVE-2023-30797"))
    
    cpe_connection = DatabaseConnection("side_data/titan_wp1b.db")
    print(get_repo_by_cpe_product_name(["locust"],cpe_connection.get_instance()))
    # remove_duplicate_func_from_dir("functions/chengran_10", "functions/chengran_10/random_split_test.json")