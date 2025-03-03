import requests
from urllib.parse import urljoin, urlparse
import time
import pandas as pd
# import numpy as np
import ast
from bs4 import BeautifulSoup
import re,os,sys
sys.path.append('./')

from config import SCRAPING_TIMEOUT,GITHUB_API_KEYS
from inner_lib import get_full_domain, with_timeout
from html_parse import DomainProcessor
sys.path.append('../')
from lib import make_github_api_request


class SynkScraper():
    def __init__(self,cve_id, products) -> None:
        self.cve_id = cve_id
        self.products = products
        self.domain_url = "https://security.snyk.io"
        
    def get_report_list(self):
        report_search_url = f"https://security.snyk.io/vuln?search={self.cve_id}"
        response = requests.get(report_search_url)
        webpage_content = response.content

        # Step 2: Parse the HTML
        soup = BeautifulSoup(webpage_content, 'html.parser')

        # Step 3: Find the table
        # Assume the table has a specific id or class. Adjust the selector as needed.
        table = soup.find('table', 
                        #   {'id': 'table-id'}
                          )  # Replace 'table-id' with the actual table id
        if table == None: #no report founded in snyk DB
            return [] 
        # Step 4: Extract table headers
        headers = ["url"]
        for th in table.find_all('th'):
            headers.append(th.text.strip())

        # Step 5: Extract table rows
        rows = []
        report_list= []
        
        for tr in table.find_all('tr'):
            cells = tr.find_all('td')
            if len(cells) > 0:
                row = []
                # Get the href link from the first td
                link = cells[0].find('a', href=True)
                if link:
                    href = link['href']
                    report_list.append(f"{self.domain_url}/{href}")
                else:
                    href = None
                    
                # row.append(href)
                # # Extract text from the rest of the cells
                # row.extend([cell.text.strip() for cell in cells])
                # rows.append(row)

        # df = pd.DataFrame(rows, columns=headers)
        # print(report_list)                
        return report_list
    class SnykProcessor(DomainProcessor): #https://security.snyk.io/vuln/SNYK-ALPINE320-K3S-7012467
        def __init__(self, url, products) -> None:
            super().__init__(url, products)
            self.domain = f"https://{get_full_domain(url)}/"
        @with_timeout(SCRAPING_TIMEOUT)
        def html_parse(self):
            
            for attempt in range(3):
                try:
                    page = requests.get(self.url)
                    break
                except requests.exceptions.ChunkedEncodingError:
                    time.sleep(1)
            else:
                return "",[] # failed to requests.get()
            soup = BeautifulSoup(page.content, "html.parser")
            next_refs =[]
            # description
            sub_soup =None
            try:
                sub_soups = soup.find_all("div", {"class": "markdown-section"})
            except Exception as e:
                print(f"BeautifulSoup failed on Snyk.io: {self.url}")
                # sub_soup = soup
            for sub_soup in sub_soups:
                tmp = [ urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
                next_refs = [*next_refs, *tmp]
            next_refs = self.filter_refs(next_refs)
            # print(next_refs)
            return sub_soup.text,next_refs
        
        
    def search_vfc(self):
        report_list = self.get_report_list()
        total_vfcs = []
        for report_url in report_list:
            proc = self.SnykProcessor(report_url, self.products)
            try:
                tmp, next_refs = proc.html_parse()
                vfcs = proc.filter_vfc(next_refs,[])
                total_vfcs = [*total_vfcs, *vfcs]
            except Exception as e:
                print("Failed in proc.html_parse() for snyk.io")
            
        return total_vfcs
    
    
class UbuntuScraper():
    def __init__(self,cve_id, products) -> None:
        self.cve_id = cve_id
        self.products = products
        self.domain_url = "https://ubuntu.com/security"
    
    
    class UbuntuProcessor(DomainProcessor): #https://security.snyk.io/vuln/SNYK-ALPINE320-K3S-7012467
        def __init__(self, url, products) -> None:
            super().__init__(url, products)
            self.domain = f"https://{get_full_domain(url)}/"
        @with_timeout(SCRAPING_TIMEOUT)
        
        
        def has_references_h2(self,tag):
            h2 = tag.find('h2')
            return h2 and h2.text.strip() == "References"
        def html_parse(self):
            
            for attempt in range(3):
                try:
                    page = requests.get(self.url)
                    break
                except requests.exceptions.ChunkedEncodingError:
                    time.sleep(1)
            else:
                return "",[] # failed to requests.get()
            soup = BeautifulSoup(page.content, "html.parser")
            next_refs =[]

            # description
            sub_soup =None
            try:
                divs_with_references = soup.find_all('div', class_='col-9', recursive=True)
                sub_soups = [div for div in divs_with_references if self.has_references_h2(div)]
            except Exception as e:
                print(f"BeautifulSoup failed on {self.domain}: {self.url}")
                # sub_soup = soup
            for sub_soup in sub_soups:
                tmp = [ urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
                next_refs = [*next_refs, *tmp]
            next_refs = self.filter_refs(next_refs)
            # print(next_refs)
            return "",next_refs
        
    def search_vfc(self):
        url = f"{self.domain_url}/{self.cve_id}"
        total_vfcs = []
        proc = self.UbuntuProcessor(url, self.products)
        try:
            tmp, next_refs = proc.html_parse()
            vfcs = proc.filter_vfc(next_refs,[])
            total_vfcs = [*total_vfcs, *vfcs]
        except Exception as e:
            print(f"Failed in proc.html_parse() for {url}:\n{e}")
            
        return total_vfcs
    
    
class UbuntuScraper():
    def __init__(self,cve_id, products) -> None:
        self.cve_id = cve_id
        self.products = products
        self.domain_url = "https://ubuntu.com/security"
    
    
    class UbuntuProcessor(DomainProcessor): #https://security.snyk.io/vuln/SNYK-ALPINE320-K3S-7012467
        def __init__(self, url, products) -> None:
            super().__init__(url, products)
            self.domain = f"https://{get_full_domain(url)}/"
        @with_timeout(SCRAPING_TIMEOUT)
        
        
        def has_references_h2(self,tag):
            h2 = tag.find('h2')
            return h2 and h2.text.strip() == "References"
        def html_parse(self):
            
            for attempt in range(3):
                try:
                    page = requests.get(self.url)
                    break
                except requests.exceptions.ChunkedEncodingError:
                    time.sleep(1)
            else:
                return "",[] # failed to requests.get()
            soup = BeautifulSoup(page.content, "html.parser")
            next_refs =[]

            # description
            sub_soup =None
            try:
                divs_with_references = soup.find_all('div', class_='col-9', recursive=True)
                sub_soups = [div for div in divs_with_references if self.has_references_h2(div)]
            except Exception as e:
                print(f"BeautifulSoup failed on {self.domain}: {self.url}")
                # sub_soup = soup
            for sub_soup in sub_soups:
                tmp = [ urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
                next_refs = [*next_refs, *tmp]
            next_refs = self.filter_refs(next_refs)
            # print(next_refs)
            return "",next_refs
        
    def search_vfc(self):
        url = f"{self.domain_url}/{self.cve_id}"
        total_vfcs = []
        proc = self.UbuntuProcessor(url, self.products)
        try:
            tmp, next_refs = proc.html_parse()
            vfcs = proc.filter_vfc(next_refs,[])
            total_vfcs = [*total_vfcs, *vfcs]
        except Exception as e:
            print(f"Failed in proc.html_parse() for {url}:\n{e}")
            
        return total_vfcs
        
class GithubAdvisoriesScraper():
    def __init__(self,cve_id, products) -> None:
        self.cve_id = cve_id
        self.products = products
        self.domain_url = "https://github.com/advisories"

  
    def search_vfc(self):
        api_url = f"https://api.github.com/advisories"
        total_vfcs = []
        next_refs = []
        params = {
            'cve_id': self.cve_id,  
        }
        # response = requests.get(api_url, params=params)
        response = make_github_api_request(url=api_url, params=params, api_keys = GITHUB_API_KEYS)
        if response.status_code != 200: 
            print(f"Failed on Github Advisories: {api_url}")
            return []
        else:
            data = response.json()
            for entry in data:
                next_refs = [*next_refs,*entry["references"]]
                
        proc = DomainProcessor(url="",products=self.products)
        total_vfcs = proc.filter_vfc(next_refs, [])
        return total_vfcs    
    
class OsvDevScraper():
    def __init__(self,cve_id, products) -> None:
        self.cve_id = cve_id
        self.products = products
        self.domain_url = "https://osv.dev"

  
    def search_vfc(self):
        api_url = f"https://api.osv.dev/v1/vulns/{self.cve_id}"
        total_vfcs = []
        next_refs = []
        
        response = requests.get(api_url,)
        if response.status_code == 404:
            print(f"Bug not found")
            return []
        elif response.status_code != 200: 
            print(f"Failed on osv.dev: {api_url}")
            print(response.content)
            return []
        else:
            data = response.json()
            try:
                for ref in data["references"]:
                    next_refs.append(ref["url"])
            except Exception as e:
                print("Failed to get references from API response")
                
        proc = DomainProcessor(url="",products=self.products)
        total_vfcs = proc.filter_vfc(next_refs, [])
        return total_vfcs    
        
if __name__ == "__main__": #testing
    products= ""
    scraper = GithubAdvisoriesScraper("CVE-2022-27651", products)
    total_vfcs=  scraper.search_vfc()
    print(total_vfcs)
    # scraper.get_report_list()
    
    # url = "https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMCONTAINERNETWORKINGPLUGINSPLUGINSMAINBRIDGE-5776177"
    
    # proc = scraper.SnykProcessor(url, products)
    # tmp, next_refs = proc.html_parse()
    # vfcs = proc.filter_vfc(next_refs,[])
    # print(vfcs)
    