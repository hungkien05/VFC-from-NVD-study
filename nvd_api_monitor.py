#note: change check_if_commit_exist in lib.py to restore normal monitoring

import csv
import os
import time
import requests, config
import json, curl,datetime
from datetime import datetime, timedelta
from commit_github import crawl_diff as github_crawl
from commit_gitlab import crawl_commit as gitlab_crawl
from commit_bitbucket import crawl_commit as bitbucket_crawl
from lib import dump_jsonl
from timeloop import Timeloop
from urllib.parse import quote
#initialize timeloop obj
tl = Timeloop()

# NVD API endpoint for CVEs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
save_dir = None
base_save_dir = "update"
# JSON file to store the CVE data
CVE_DATA_FILE = "cve_data.json"

class ResponseHandler:
    def __init__(self) -> None:
        self.github_data = []
        self.gitlab_data = []
        self.bitbucket_data = []
        self.vuln_status_dict = dict()

    def parse_response(self,resp): #parse response of NVD, to extract CVEs and their corresponding commits, then put them into json file

        global save_dir
        is_explicit = False
        for item in resp["vulnerabilities"]:
            #todo: check if this cve is modified or new
            patch_urls = []
            github_urls = []
            gitlab_urls = []
            bitbucket_urls = []
            cve = item["cve"]
            vuln_status = cve["vulnStatus"]
            if vuln_status not in self.vuln_status_dict:
                self.vuln_status_dict[vuln_status] =1
            else:
                self.vuln_status_dict[vuln_status] +=1
            id= cve["id"]
            if id == "CVE-2024-0690":
                a=1
            refs = cve["references"]
            for ref in refs:
                try:
                    tags = ref["tags"]
                except Exception as e:
                    continue
                if "Patch" in tags:
                    url = ref["url"]
                    if "github.com" in url:
                        github_urls.append(url)
                        is_explicit = True
                    elif "gitlab.com" in url:
                        gitlab_urls.append(url)
                        is_explicit = True
                    elif "bitbucket.org" in url:
                        bitbucket_urls.append(url)
                        is_explicit = True
                        
            if not is_explicit:
                a=1 #todo: add the script of get implicit VFCs
            if len(github_urls) >0:
                self.github_data.append({"cve_id": id, "patch_url": github_urls})
            if len(gitlab_urls) >0:
                self.gitlab_data.append({"cve_id": id, "patch_url": gitlab_urls})
            if len(bitbucket_urls) >0:
                self.bitbucket_data.append({"cve_id": id, "patch_url": bitbucket_urls})
        
    def output(self,current_time): 
        global save_dir
        # with open(f"{save_dir}/github.json", "w") as f:
        #     json.dump(self.github_data, f, indent=4)
        # with open(f"{save_dir}/gitlab.json", "w") as f:
        #     json.dump(self.gitlab_data, f, indent=4)
        # with open(f"{save_dir}/bitbucket.json", "w") as f:
        #     json.dump(self.bitbucket_data, f, indent=4)
        
        dump_jsonl(self.github_data, f"{save_dir}/github.jsonl")
        dump_jsonl(self.gitlab_data, f"{save_dir}/gitlab.jsonl")
        dump_jsonl(self.bitbucket_data, f"{save_dir}/bitbucket.jsonl")
            
        # update_patch_json()
        #log the csv file
        with open(f'{save_dir}/log.csv', 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if csvfile.tell() == 0:
                writer.writerow(['Date', 'Github', 'Gitlab', "Bitbucket"]) 
            new_data = [
                [current_time, len(self.github_data), len(self.gitlab_data), len(self.bitbucket_data)],  
            ]
            for row in new_data:
                writer.writerow(row)
    
    
def update_patch_json(): # update current commit or add new commit, each platform has its own code (due to different in api)
    global save_dir
    github_crawl(f"{save_dir}/github.jsonl", save_dir)
    gitlab_crawl(f"{save_dir}/gitlab.jsonl", save_dir)
    bitbucket_crawl(f"{save_dir}/bitbucket.jsonl",save_dir)
    
    
def split_ranges_for_api(raw_start_date, raw_end_date, max_days=120):
    # Convert strings to datetime objects
    start_date = datetime.strptime(raw_start_date, "%d-%m-%Y")
    end_date = datetime.strptime(raw_end_date, "%d-%m-%Y")

    # Initialize ranges
    ranges = []
    current_start = start_date

    while current_start < end_date:
        # Calculate the next end date (120 days later or the actual end date)
        current_end = min(current_start + timedelta(days=max_days - 1), end_date)
        # ranges.append((current_start.strftime("%d-%m-%Y"), current_end.strftime("%d-%m-%Y")))
        ranges.append((current_start, current_end))
        current_start = current_end + timedelta(days=1)

    for (mod_start_date, mod_end_date) in ranges:
        check = fetch_cve_data(mod_start_date=mod_start_date, mod_end_date = mod_end_date)
    # return ranges
    return check

def fetch_cve_data(mod_start_date=None, mod_end_date = None):
    """
    Fetch CVE data from the NVD API. If mod_start_date is provided,
    it fetches CVEs modified since that date.
    """
    params = {
        'resultsPerPage': 2000,  
    }
    headers = {
        "apiKey": config.NVD_API_KEY,  # NVD API key
        'User-Agent': 'python-requests/2.31.0',
    }
    resp_handler = ResponseHandler()
    # mod_start_date = mod_start_date - timedelta(days=16) # uncomment if want to monitor longer than 1 days
    if mod_start_date:
        # choose date range based on Modified or Published ?
        # params['lastModStartDate'] = mod_start_date.strftime('%Y-%m-%dT00:00:00.000+08:00')
        # params['lastModEndDate'] = mod_end_date.strftime('%Y-%m-%dT00:00:00.000+08:00')
        params['pubStartDate'] = mod_start_date.strftime('%Y-%m-%dT00:00:00.000+08:00')
        params['pubEndDate'] = mod_end_date.strftime('%Y-%m-%dT00:00:00.000+08:00')
    print(params)
    # response = requests.get(NVD_API_URL, params=params)
    start_index = 0
    total_result =-1 #initialize total_result variable
    while True:
        print(f"calling NVD API with start_index = {start_index} ")
        params['startIndex'] = start_index
        # url_params = f"lastModStartDate={params['lastModStartDate']}&lastModEndDate={params['lastModEndDate']}"
        
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers)
        except Exception as e:
            time.sleep(3)
            print(f"Error {e}. Request URL = {response.url}")
            continue
        if response.status_code != 200:
            print(f"Error fetching CVEs: {response.text}.\n Status code:", response.status_code)
            if response.status_code ==503: ## server error 503 then call the API again
                print("Calling API again.........")
                time.sleep(3)
                continue
            return False
        print("-------done calling API--------")
        cve_data = response.json()
        if total_result <0:
            total_result = int(cve_data["totalResults"])
        resp_handler.parse_response(cve_data)
        print("done parse_response")
        start_index +=2000
        if start_index >total_result: #no more page to read
            break
    resp_handler.output(mod_start_date)
    return True
def save_cve_data(data, mode='w'):
    """
    Save or append CVE data to a JSON file.
    """
    with open(CVE_DATA_FILE, mode) as file:
        json.dump(data, file, indent=2)


@tl.job(interval=timedelta(seconds=3600))
def main(): #main function
    """
    Update the CVE data file with new and modified CVEs since the last update.
    """
    global save_dir
    # Try to read the existing data to find the last update date
    # try:
    #     with open(CVE_DATA_FILE, 'r') as file:
    #         existing_data = json.load(file)
    #         last_update_date = existing_data.get('timestamp')
    # except (FileNotFoundError, json.JSONDecodeError):
    #     last_update_date = None

    current_time = datetime.now()
    current_time = current_time - timedelta(days=2)
    current_date = current_time.strftime('%d_%m_%Y')
    current_date = "09_01_2025" # uncomment this if want to manually set current_date for file naming
    save_dir = f"{config.BASE_METADATA_DIR}/{current_date}"
    function_save_dir = f"{config.BASE_FUNCTION_DIR}/{current_date}"
    os.makedirs(save_dir, exist_ok=True)
    os.makedirs(function_save_dir, exist_ok=True)
    last_update_date = current_time
    #normal monitoring
    if last_update_date:
        mod_start_date=last_update_date - timedelta(days=1)
        mod_end_date = mod_start_date + timedelta(days=1)
        # uncomment this if want to monitoring specific long time duration
        # mod_start_date = datetime.strptime("20-03-2024", "%d-%m-%Y")
        # mod_end_date = datetime.strptime("18-11-2024", "%d-%m-%Y")  
        
        check = fetch_cve_data(mod_start_date=mod_start_date, mod_end_date = mod_end_date)
    else:
        check = fetch_cve_data()

    #monitoring specific long time duration
    # check=split_ranges_for_api("28-02-2024", "09-01-2025")    
    # check=True
    
        

if __name__ == "__main__":
    main()
    # tl.start(block=True)
