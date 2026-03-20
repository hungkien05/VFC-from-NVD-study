from datetime import datetime
import json
import os
import random
import time
import requests
import config
from lib import convert_datetime_to_UTC, create_file_if_not_exists, handle_github_rate_limit, make_github_api_request

GH_TOKEN = ""
GL_TOKEN = ""
BITBUCKET_TOKEN = ""



class Platform_API_Caller:
    def __init__(self, repo, commit ="") -> None:
        self.count_call_api =0
        self.repo = repo
        self.commit = commit
        if commit == None:
            self.commit=""
        self.commit_url = ""
    def get_parent_commit(self) -> str:
        pass
    def get_file_content(self, commit, file_path):
        pass
    def get_commit_url(self):
        return self.commit_url
    def get_commit_datetime(self, count_try):
        pass
    def search_commit_by_keywords(repo_name, keywords):
        pass
    def get_commit_message(self,commit):
        pass
    
class GitHub_API_Caller(Platform_API_Caller):
    def __init__(self, repo, commit ="") -> None:
        super().__init__(repo, commit)
        self.fail_log_path = config.FAIL_LOG_PATH
        create_file_if_not_exists(self.fail_log_path)
        self.api_keys = config.GITHUB_API_KEYS
        self.commit_url = f"https://github.com/{self.repo}/commit/{self.commit}"
        self.headers = {
            'Authorization': f'Bearer {GH_TOKEN}',
            'Accept': 'application/vnd.github.v3+json',
        }
        self.api_url = f"https://api.github.com/repos/{self.repo}/commits/{self.commit}"
        self.datetime = None
        self.response = None
    def get_parent_commit(self,) -> str:
        if self.count_call_api >2:
            self.count_call_api = 0
            return None
        data =None
        
        # response = requests.get(self.api_url, headers=self.headers)
        response = make_github_api_request(url=self.api_url, params={})
        self.response = response
        if response.status_code ==200:
            data = response.json()
        else:
            print(f"Error getting parent commit {self.api_url}: {response.content}")
            self.count_call_api +=1
            time.sleep(5)
            return self.get_parent_commit()
        
        try:
            self.parent_commit = data["parents"][0]["sha"]
            self.date = self.get_commit_datetime(0, data)
        except Exception as e:
            return None
        # print(self.parent_commit)
        return self.parent_commit
    
    def get_file_content(self, commit, file_path):
        #start request API
        download_url = f'https://raw.githubusercontent.com/{self.repo}/{commit}/{file_path}'
        response = requests.get(download_url,headers=self.headers)
        if response.status_code ==200:
            return response.text
        return None
    
    def get_commit_datetime(self, count_try, commit_data = None):
        if commit_data == None:
            response = requests.get(self.api_url, headers=self.headers)
            commit_datetime = None
            if response.status_code == 200:
                commit_data = response.json()  
            else:
                print(f"Failed to fetch commit information. Status code: {response.status_code}: {response.content}")
                time.sleep(5)
                if count_try >3:
                    print(f"Fail calling API too many times: {self.api_url}")
                    return None
                commit_datetime = self.get_commit_datetime(count_try+1, commit_data)
        commit_datetime = commit_data['commit']['author']['date']  # Assuming the datetime is in ISO 8601 format
        commit_datetime = convert_datetime_to_UTC(commit_datetime)
        return commit_datetime
    def search_commit_by_keywords_old( self,keywords):
        api_commit_url = f'https://api.github.com/repos/{self.repo}/commits'
        params = {
            'per_page':100
        }
        commits_found = []
        while api_commit_url:
            response = requests.get(api_commit_url, headers=self.headers, params=params)
            if response.status_code == 200:
                commits = response.json()
                for commit in commits:
                    for keyword in keywords:
                        if keyword.lower() in commit['commit']['message'].lower():
                            commits_found.append((commit['sha'], commit['commit']['message']))
                            break  # Only add once per commit regardless of how many keywords match
            else:
                print(f"Failed to fetch commits for {self.repo}. Status code: {response.status_code}")
            api_commit_url = response.links.get('next', {}).get('url', None)
        # Fetch commits from the repository
        
        return commits_found
    
    def search_commit_by_keywords( self,keywords, period,):
        # search_commit_api_url = f'https://api.github.com/search/commits?q=repo:{self.repo}+'
        params = {
            'per_page':100
        }
        commits_found = set()
        keywords_found =[]
        for keyword in keywords:
            keyword = keyword.lower()
            search_commit_api_url = f'https://api.github.com/search/commits?q=repo:{self.repo}+{keyword}+author-date:{period}'
            fail_count = 0
            while search_commit_api_url:
                # response = requests.get(search_commit_api_url, headers=self.headers, params=params)
                response = make_github_api_request(search_commit_api_url, params, self.api_keys)
                if response.status_code == 200:
                    fail_count = 0
                    json_data = response.json()
                    if json_data["total_count"] == 0:
                        break
                    for commit in json_data["items"]:
                        # commits_found.add((commit['sha'], commit['commit']['message']))
                        if "CVEProject" not in commit['html_url']:
                            l = len(commits_found)
                            commits_found.add(  commit['html_url'])
                            if l +1 == len(commits_found):
                                keywords_found.append(keyword)
                        # break  # Only add once per commit regardless of how many keywords match
                else:
                    print(f"Failed to fetch commits for {search_commit_api_url}. Status code: {response.status_code}")
                    print(f"Response message: {response.content}")
                    with open(self.fail_log_path, "a") as f:
                        f.write(f"{keywords[0]}\n")
                        f.write(f"Failed to fetch commits for {search_commit_api_url}. Status code: {response.status_code}\n")
                        f.write(f"Response message: {response.content}\n")
                    break
                    # is_rate_limit = handle_github_rate_limit(response)
                    # if is_rate_limit:
                    #     fail_count +=1
                    #     if fail_count >5:
                    #         break
                    #     continue
                    # else:
                    #     break
                search_commit_api_url = response.links.get('next', {}).get('url', None)
            # Fetch commits from the repository
        assert len(commits_found)== len(keywords_found)
        return list(commits_found), keywords_found
    
    def search_commit_only_within_period(self, period,):
        # search_commit_api_url = f'https://api.github.com/search/commits?q=repo:{self.repo}+'
        params = {
            'per_page':100
        }
        commits_found = set()
        keywords_found =[]
        search_commit_api_url = f'https://api.github.com/search/commits?q=repo:{self.repo}+author-date:{period}'
        fail_count = 0
        while search_commit_api_url:
            # response = requests.get(search_commit_api_url, headers=self.headers, params=params)
            response = make_github_api_request(search_commit_api_url, params, self.api_keys)
            if response.status_code == 200:
                fail_count = 0
                json_data = response.json()
                if json_data["total_count"] == 0:
                    break
                for commit in json_data["items"]:
                    # commits_found.add((commit['sha'], commit['commit']['message']))
                    if "CVEProject" not in commit['html_url']:
                        l = len(commits_found)
                        commits_found.add(  commit['html_url'])
            else:
                print(f"Failed to fetch commits for {search_commit_api_url}. Status code: {response.status_code}")
                print(f"Response message: {response.content}")
                with open(self.fail_log_path, "a") as f:
                    f.write(f"Failed to fetch commits for {search_commit_api_url}. Status code: {response.status_code}\n")
                    f.write(f"Response message: {response.content}\n")
                break
            search_commit_api_url = response.links.get('next', {}).get('url', None)
            # Fetch commits from the repository
        return list(commits_found)
    
    
    def get_commit_message(self, commit):
        self.response = make_github_api_request(url=self.api_url, params={})
        data = self.response.json()
        try:
            message = data["commit"]["message"]
        except Exception as e:
            print(f"Failed to get commit message from {commit}")
            return ""
        return 
        
    def get_random_commits(self, count=5000):
        """
        Retrieve and randomly select a specified number of commit SHAs from a GitHub repository.
        
        Args:
            
            count (int): Number of commit SHAs to randomly select (default: 5000)
        
        Returns:
            list: Randomly selected commit SHAs
        """
        
        # First, get the total number of commits in the repository
        url = f"https://api.github.com/repos/{self.repo}/commits"
        params = {"per_page": 1}
        # response = requests.get(url, headers=headers, params=params)
        response = make_github_api_request(url=url, params=params)
        
        if response.status_code != 200:
            print(f"Error: {response.status_code}")
            print(response.json())
            return []
        
        # Get total commit count from the Link header
        if "Link" in response.headers:
            link_header = response.headers["Link"]
            last_page = int(link_header.split("page=")[-1].split(">")[0])
            total_commits = last_page
        else:
            # For small repos without pagination
            total_commits = len(response.json())
        
        print(f"Total commits in repository: {total_commits}")
        
        # If there are fewer than 'count' commits, adjust the count
        if total_commits < count:
            print(f"Repository has fewer commits than requested. Returning all {total_commits} commits.")
            count = total_commits
        
        # For large repositories, we'll use random page sampling
        # to avoid hitting rate limits
        all_commits = []
        pages_to_fetch = min(100, (count // 100) + 1)
        
        # Generate random page numbers to fetch
        max_page = (total_commits // 100) + 1
        random_pages = random.sample(range(1, max_page + 1), min(pages_to_fetch, max_page))
        
        for page in random_pages:
            params = {"per_page": 100, "page": page}
            # response = requests.get(url, headers=headers, params=params)
            response = make_github_api_request(url=url, params=params)
            
            if response.status_code == 200:
                page_commits = response.json()
                all_commits.extend([commit["sha"] for commit in page_commits])
            else:
                print(f"Error fetching page {page}: {response.status_code}")
            
            # Respect GitHub's rate limits
            time.sleep(0.7)
        
        # If we have more commits than needed, randomly select the required number
        if len(all_commits) > count:
            selected_commits = random.sample(all_commits, count)
        else:
            selected_commits = all_commits
        
        return selected_commits
    
class GitLab_API_Caller(Platform_API_Caller):
    def __init__(self,repo, commit) -> None:
        super().__init__(repo, commit)
        self.commit_url = f"https://gitlab.com/{repo}/-/commit/{commit}"
        self.headers = {'PRIVATE-TOKEN': GL_TOKEN}
        repo = self.repo.replace("/", "%2F")
        self.api_url = f"https://gitlab.com/api/v4/projects/{repo}/repository/commits/{self.commit}"
        self.response = None 
    def get_parent_commit(self,) -> str:
        if self.count_call_api >2:
            self.count_call_api = 0
            return None
        data =None
        
        
        response = requests.get(self.api_url, headers=self.headers)
        self.response = response
        if response.status_code ==200:
            data = response.json()
        else:
            print(f"Error getting parent commit {self.api_url}: {response.content}")
            self.count_call_api +=1
            time.sleep(5)
            return self.get_parent_commit()
        
        try:
            self.parent_commit = data["parent_ids"][0]
            self.date = self.get_commit_datetime(0, data)
        except Exception as e:
            self.parent_commit = None
            return None
        # print(self.parent_commit)
        return self.parent_commit
    
    def get_file_content(self,commit, file_path):
        #start request API'
        download_url = f'https://gitlab.com/{self.repo}/-/raw/{commit}/{file_path}'
        response = requests.get(download_url,headers=self.headers)
        if response.status_code ==200:
            return response.text
        return None
    
    def get_commit_datetime(self,count_try, commit_data= None, ):
        if commit_data == None:
            response = requests.get(self.api_url, headers=self.headers)
            commit_datetime = None
            if response.status_code == 200:
                commit_data = response.json()
                # commit_datetime = commit_data['authored_date']  
            else:
                print(f"Failed to fetch commit information. Status code: {response.status_code}: {response.content}")
                time.sleep(5)
                if count_try >3:
                    print(f"Fail calling API too many times: {self.api_url}")
                    return None
                commit_datetime = self.get_commit_datetime(count_try+1, commit_data)
        commit_datetime = commit_data['authored_date']# Assuming the datetime is in ISO 8601 format
        commit_datetime = convert_datetime_to_UTC(commit_datetime)
        return commit_datetime

    def get_commit_message(self, commit):
        self.response = requests.get(self.api_url, headers=self.headers)
        data = self.response.json()
        try:
            message = data["message"]
        except Exception as e:
            print(f"Failed to get commit message from {commit}")
            return ""
        return message
    
class BitBucket_API_Caller(Platform_API_Caller):
    def __init__(self,repo, commit) -> None:
        super().__init__(repo, commit)
        self.commit_url = f"https://bitbucket.org/{repo}/commits/{commit}"
        self.headers = {
            'Authorization': BITBUCKET_TOKEN,
        }
        self.api_url = f"https://api.bitbucket.org/2.0/repositories/{self.repo}/commit/{self.commit}"
        self.response = None
    def get_parent_commit(self) -> str:
        if self.count_call_api >2:
            self.count_call_api = 0
            return None
        data =None
        
        response = requests.get(self.api_url, headers=self.headers)
        self.response = response
        if response.status_code ==200:
            data = response.json()
        else:
            print(f"Error getting parent commit {self.api_url}: {response.content}")
            self.count_call_api +=1
            time.sleep(5)
            return self.get_parent_commit()
        
        try:
            self.parent_commit = data["parents"][0]["hash"]
            self.date = self.get_commit_datetime(0,data)
        except Exception as e:
            self.parent_commit = None
            return None
        # print(self.parent_commit)
        return self.parent_commit
    
    def get_file_content(self, commit, file_path):
        #start request API
        download_url = f'https://bitbucket.org/{self.repo}/raw/{commit}/{file_path}'
        response = requests.get(download_url,headers=self.headers)
        if response.status_code ==200:
            return response.text
        return None
    
    def get_commit_datetime(self, count_try, commit_data =None):
        if commit_data == None:
            response = requests.get(self.api_url, headers=self.headers)
            self.response = response
            commit_datetime = None
            if response.status_code == 200:
                commit_data = response.json()
            else:
                print(f"Failed to fetch commit information. Status code: {response.status_code}: {response.content}")
                time.sleep(5)
                if count_try >3:
                    print(f"Fail calling API too many times: {self.api_url}")
                    return None
                commit_datetime = self.get_commit_datetime(count_try+1,commit_data)
        commit_datetime = commit_data["date"]  
        commit_datetime = convert_datetime_to_UTC(commit_datetime)
        return commit_datetime
    
    def get_commit_message(self, commit):
        self.response = requests.get(self.api_url, headers=self.headers)
        data = self.response.json()
        try:
            message = data["rendered"]["message"]["raw"]
        except Exception as e:
            print(f"Failed to get commit message from {commit}")
            return ""
        return message