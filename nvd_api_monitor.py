import csv
import os
import requests, config
import json, curl,datetime
from datetime import datetime, timedelta
from commit_github import crawl_diff as github_crawl
from commit_gitlab import crawl_commit as gitlab_crawl
from commit_bitbucket import crawl_commit as bitbucket_crawl
from get_function import get_functions
from patch_parser import process_function
from timeloop import Timeloop

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
                    elif "gitlab.com" in url:
                        gitlab_urls.append(url)
                    elif "bitbucket.org" in url:
                        bitbucket_urls.append(url)
            if len(github_urls) >0:
                self.github_data.append({"cve_id": id, "patch_url": github_urls})
            if len(gitlab_urls) >0:
                self.gitlab_data.append({"cve_id": id, "patch_url": gitlab_urls})
            if len(bitbucket_urls) >0:
                self.bitbucket_data.append({"cve_id": id, "patch_url": bitbucket_urls})
        
    def output(self,current_time):
        global save_dir
        with open(f"{save_dir}/github.json", "w") as f:
            json.dump(self.github_data, f, indent=4)
        with open(f"{save_dir}/gitlab.json", "w") as f:
            json.dump(self.gitlab_data, f, indent=4)
        with open(f"{save_dir}/bitbucket.json", "w") as f:
            json.dump(self.bitbucket_data, f, indent=4)
            
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
    github_crawl(f"{save_dir}/github.json", save_dir)
    gitlab_crawl(f"{save_dir}/gitlab.json", save_dir)
    bitbucket_crawl(f"{save_dir}/bitbucket.json",save_dir)

def split_date_range(start_date, end_date, max_days=120):
    """
    Split a date range into chunks of max_days or less.
    Returns a list of (chunk_start_date, chunk_end_date) tuples.
    """
    chunks = []
    current_start = start_date
    
    while current_start <= end_date:
        # Calculate the end date for this chunk
        current_end = min(current_start + timedelta(days=max_days-1), end_date)
        chunks.append((current_start, current_end))
        
        # Move to the next chunk
        current_start = current_end + timedelta(days=1)
    
    return chunks

def fetch_chunk_data(chunk_start, chunk_end, resp_handler):
    """
    Fetch CVE data for a specific date chunk (120 days or less).
    """
    params = {
        'resultsPerPage': 2000,
    }
    
    if chunk_start and chunk_end:
        # params['lastModStartDate'] = chunk_start.strftime('%Y-%m-%dT00:00:00.000+08:00')
        # params['lastModEndDate'] = chunk_end.strftime('%Y-%m-%dT00:00:00.000+08:00')
        params['pubStartDate'] = chunk_start.strftime('%Y-%m-%dT00:00:00.000+08:00')
        params['pubEndDate'] = chunk_end.strftime('%Y-%m-%dT00:00:00.000+08:00')
    
    print(f"API parameters: {params}")
    
    start_index = 0
    total_result = -1  # initialize total_result variable
    
    while True:
        print(f"Calling NVD API with start_index = {start_index}")
        params['startIndex'] = start_index
        headers = {
            "apiKey":   config.NVD_API_KEY# NVD API key
        }
        response = requests.get(NVD_API_URL, params=params, headers=headers)
        print(requests.utils.unquote(response.url))
        if response.status_code != 200:
            print(f"Error fetching CVEs: {response.text}.\nStatus code: {response.status_code}")
            return False
        
        print("Done calling API")
        cve_data = response.json()
        
        if total_result < 0:
            total_result = int(cve_data["totalResults"])
        
        resp_handler.parse_response(cve_data)
        print("Done parse_response")
        
        start_index += 2000
        if start_index > total_result:  # no more page to read
            break
    
    return True

def fetch_cve_data(mod_start_date=None, mod_end_date=None):
    """
    Fetch CVE data from the NVD API. If mod_start_date is provided,
    it fetches CVEs modified since that date.
    
    Handles unlimited date ranges by splitting into chunks of 120 days.
    """
    resp_handler = ResponseHandler()
    
    if mod_start_date and mod_end_date:
        # Calculate the number of days between start and end dates
        delta = (mod_end_date - mod_start_date).days
        
        if delta > 120:
            # If the date range is more than 120 days, split it into chunks
            date_chunks = split_date_range(mod_start_date, mod_end_date)
            print(f"Date range exceeds 120 days ({delta} days). Splitting into {len(date_chunks)} chunks.")
            
            for i, (chunk_start, chunk_end) in enumerate(date_chunks):
                print(f"Processing chunk {i+1}/{len(date_chunks)}: {chunk_start.strftime('%Y-%m-%d')} to {chunk_end.strftime('%Y-%m-%d')}")
                success = fetch_chunk_data(chunk_start, chunk_end, resp_handler)
                if not success:
                    return False
        else:
            # If the date range is 120 days or less, fetch directly
            success = fetch_chunk_data(mod_start_date, mod_end_date, resp_handler)
            if not success:
                return False
    else:
        # If no date range is provided, fetch the default data
        success = fetch_chunk_data(None, None, resp_handler)
        if not success:
            return False
    
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
    current_date = "010125_311225" # uncomment this if want to manually set current_date for file naming
    save_dir = f"{config.BASE_METADATA_DIR}/{current_date}"
    function_save_dir = f"{config.BASE_FUNCTION_DIR}/{current_date}"
    os.makedirs(save_dir, exist_ok=True)
    os.makedirs(function_save_dir, exist_ok=True)
    last_update_date = current_time
    if last_update_date:
        mod_start_date=last_update_date - timedelta(days=1)
        mod_end_date = mod_start_date + timedelta(days=1)
        # uncomment this if want to monitoring specific long time duration
        mod_start_date = datetime.strptime("01-01-2025", "%d-%m-%Y")
        mod_end_date = datetime.strptime("31-12-2025", "%d-%m-%Y")  
        
        check = fetch_cve_data(mod_start_date=mod_start_date, mod_end_date = mod_end_date)
    else:
        check = fetch_cve_data()

    if check:
        # parse_response(current_time,new_data)
        update_patch_json()
        count =0
        count_func=0
        for platform in ["github", "gitlab", "bitbucket"]:
            os.makedirs(f"{save_dir}/{platform}", exist_ok=True)
            # get_functions( f"{save_dir}/{platform}",platform)
            commit_save_dir = f"{save_dir}/{platform}"
            print(f"Start process_function\nData will be saved at {function_save_dir}")
            
            for filename in os.listdir(commit_save_dir):
                count+=1
                # print(count)
                file_path = os.path.join(commit_save_dir, filename)
                if not os.path.isfile(file_path):
                    continue
                count_func += process_function(file_path,platform,function_save_dir)
        

if __name__ == "__main__":
    main()
    # tl.start(block=True)
