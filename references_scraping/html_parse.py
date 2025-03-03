import requests
from urllib.parse import urljoin, urlparse
import time
import pandas as pd
import numpy as np
import ast
from bs4 import BeautifulSoup
import re
from config import SCRAPING_TIMEOUT
from inner_lib import get_full_domain, with_timeout, dump_pickle, is_non_alphanumeric, remove_non_alphanumeric


class DomainProcessor:
    def __init__(self,url,products) -> None:
        self.products= []
        for product in products.split("|"):
            if not is_non_alphanumeric(product):
                self.products.append(remove_non_alphanumeric(product))
        if len(self.products)<1:
            self.products= ['']
        self.url = url
        pass
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        pass
    def find_vfc(self, web_content):
        pattern = r'https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|sourceforge\.net)/.*/' + re.escape(products) + r'/commit/[a-f0-9]+'
        urls = re.findall(pattern, web_content, re.IGNORECASE)
        sourceforge_pattern = r'https?://(?:www\.)?(?:sourceforge\.net)/.*/' + re.escape(self.products) + r'/code/ci/[a-f0-9]+'
        sourceforge_urls = re.findall(sourceforge_pattern, web_content, re.IGNORECASE)
        urls = [*urls, *sourceforge_urls]
        return urls
    def filter_refs(self, ref_list, ):
        updated_ref_list = ref_list.copy()
        for ref in ref_list:
            if "nvd.nist.gov" in ref:
                updated_ref_list.remove(ref)
        return updated_ref_list
    def filter_vfc(self, link_list, git_repo_list):
        product_pattern = self.products[0]
        if len(self.products) >1:
            for product in self.products[1:]:
                product_pattern += f"|{product}"
            product_pattern = f"({product_pattern})"
        if len(product_pattern) <1:# no product for this row in nvd data path => has to fix regex into [a-z][0-9]+
            product_pattern = "[a-z0-9-_]+"
        bitbucket_issue_pattern =  r"http(s?)://bitbucket.org/([^/]+/[^/]+)/(issues|pull-requests)/([0-9]+)S*s*"
        gitlab_issue_pattern = r"http(s?)://gitlab.com/([0-9a-z/]+)(/-)?/(issues|merge_requests)/([0-9]+)\S*\s*"
        github_issue_pattern = r"http(s?)://github.com/([^/]+/[^/]+)/(issues|pull)/([0-9]+)\S*\s*"
        pattern = r'https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|sourceforge\.net)/.*/' + rf'{product_pattern}' + r'/commit/[a-f0-9]+'
        pattern_str = f'https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|sourceforge\.net)/.*/{product_pattern}/commit/[a-f0-9]+'
        # pattern = re.compile(pattern_str)
        vfc_list = []
        sourceforge_pattern = r'https?://(?:www\.)?(?:sourceforge\.net)/.*/' + rf'{product_pattern}' + r'/code/ci/[a-f0-9]+'
        # dump_pickle(pattern, "pickle/tmp/pattern.pkl")
        
        
        for link in link_list:
            # dump_pickle(link, "pickle/tmp/link.pkl")
            if re.match(pattern, link) or re.match(github_issue_pattern, link) or  re.match(sourceforge_pattern, link) or re.match(bitbucket_issue_pattern, link)  or re.match(gitlab_issue_pattern, link):
                if len(git_repo_list)>0:
                    for git_repo in git_repo_list:
                        if git_repo in link:
                            vfc_list.append(link)
                else: #if cannot find any git repo, just accept all vfcs
                    vfc_list.append(link)
        return vfc_list
    
class OtherProcessor(DomainProcessor):
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        self.domain = f"https://{get_full_domain(url)}/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        if "github.com" in self.url or "gitlab.com" in self.url or "bitbucket.com" in self.url: #skip those git-related link
            return "", []
        page = None
        try:
            page = requests.get(self.url)
        except Exception:
            return "",[]
        soup = BeautifulSoup(page.content, "html.parser")
        sub_soup = soup
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        return sub_soup.text,next_refs
    
class OracleProcessor(DomainProcessor): #https://www.oracle.com/security-alerts/bulletinapr2015.html
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        self.domain = f"https://{get_full_domain(url)}/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = None
        try:
            page = requests.get(self.url)
        except Exception:
            return "",[]
        soup = BeautifulSoup(page.content, "html.parser")
        sub_soup = soup
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        return sub_soup.text,next_refs
    
    
class OpenwallProcessor(DomainProcessor):
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = "https://www.openwall.com"
        
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        _RE_COMBINE_WHITESPACE = re.compile(r"\s+")
        # self.web_content = x
        sub_soup = soup.find_all("pre")[0]
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        return sub_soup.text,next_refs
    
    # def find_vfc(self, web_content, products):
    
class UbuntuProcessor(DomainProcessor):
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = "https://www.ubuntu.com"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        found_res = soup.find_all("section")
        if len(found_res) <1: # cannot decode utf-8, use other decoding
            soup = BeautifulSoup(page.content,"html.parser",from_encoding="iso-8859-1") 
            found_res = soup.find_all("section")
        sub_soup = found_res[0]    
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        return sub_soup.text,next_refs
    
class BugzillaRedHatProcessor(DomainProcessor):
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = "https://bugzilla.redhat.com/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        found_res = soup.find_all("form", id="changeform")
        if len(found_res) <1: # cannot decode utf-8, use other decoding
            soup = BeautifulSoup(page.content,"html.parser",from_encoding="iso-8859-1") 
            found_res = soup.find_all("form", id="changeform")
        if len(found_res) <1:
            sub_soup = soup
        else:
            sub_soup  = found_res[0]
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        return sub_soup.text,next_refs

class AccessRedHatProcessor(DomainProcessor):
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = "https://access.redhat.com/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup = None
        found_soup = soup.find_all("div", id="overview") #first format
        if len(found_soup) <1: 
            found_soup = soup.find_all("div", id="tabs")  #second HTML  #first format
        if len(found_soup) <1: #if not belong to any format, just take the whole HTML for parsing
            sub_soup = soup
        if sub_soup == None:
            sub_soup = found_soup[0]
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        return sub_soup.text,next_refs
    
class SecurityGentooProcessor(DomainProcessor):
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = "https://security.gentoo.org/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        _RE_COMBINE_WHITESPACE = re.compile(r"\s+")
        sub_soup = soup.select("body>div")[0]
        # sub_soup  = soup.find_all("body")[0]
        # sub_soup  = sub_soup.find_all("div", )[0]
        # x = _RE_COMBINE_WHITESPACE.sub(" ", sub_soup)
        # sub_soup = x
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        next_refs = self.filter_refs(next_refs)
        return sub_soup.text,next_refs
    
class OpensuseProcessor(DomainProcessor): ## todo: handle when soup.findall return nothing
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = f"https://{get_full_domain(url)}/"
        print(self.domain)
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup =None
        try:
            sub_soup = soup.find_all("div", {"class": "email-body"})[0]
        except Exception as e:
            print(f"BeautifulSoup failed on Openuse: {self.url}")
            sub_soup = soup
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        next_refs = self.filter_refs(next_refs)
        return sub_soup.text,next_refs
    
class FedoraProjectProcessor(DomainProcessor): #https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126816.html
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = f"https://{get_full_domain(url)}/"
        print(self.domain)
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup = None
        found_soup = soup.find_all("div", {"class": "email-body"}) #first format
        if len(found_soup) <1: 
            found_soup = soup.find_all("pre") #second HTML  #first format
        if len(found_soup) <1: #if not belong to any format, just take the whole HTML for parsing
            sub_soup = soup
        if sub_soup == None:
            sub_soup = found_soup[0]
        try: # todo: exclude ipv6 url
            next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        except Exception as e:
            next_refs = []
        # for a in sub_soup.find_all('a'):
        #     if a.get('href') is not None:
        #         ref = urljoin(self.domain, a.get('href'))
        #         next_refs.append(ref)
        next_refs = self.filter_refs(next_refs)
        next_refs = next_refs[:-2] #last 2 refs are just fedora own links, not related to NVD/CVE
        return sub_soup.text,next_refs
    
class DebianProcessor(DomainProcessor): #https://lists.debian.org/debian-security-announce/2017/msg00188.html
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        
        self.domain = f"https://{get_full_domain(url)}/"
        print(self.domain)
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup = None
        found_soup = soup.find_all("pre") #second HTML  #first format
        if len(found_soup) <1: #if not belong to any format, just take the whole HTML for parsing
            sub_soup = soup
        if sub_soup == None:
            sub_soup = found_soup[0]
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        next_refs = self.filter_refs(next_refs)
        return sub_soup.text,next_refs
    
class MarcInfoProcessor(DomainProcessor): #http://marc.info/?l=php-internals&m=147921016724565&w=2
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        self.domain = f"http://{get_full_domain(url)}/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        # print(f"{self.url}")
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup = None
        found_soup = soup.find_all("pre")
        if len(found_soup) <1: #if not belong to any format, just take the whole HTML for parsing
            sub_soup = soup
        if sub_soup == None:
            sub_soup = found_soup[0]
            for b_tag in sub_soup.find_all('b'):
                b_tag.decompose()
            # print(str(sub_soup))
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        next_refs = self.filter_refs(next_refs)
        return sub_soup.text,next_refs
        
class PacketStormProcessor(DomainProcessor): #https://packetstormsecurity.com/files/173990/Diebold-Nixdorf-Vynamic-View-Console-5.3.1-DLL-Hijacking.html
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        self.domain = f"https://{get_full_domain(url)}/"
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup = None
        found_soup = soup.find_all("dl", {"class": "file first"})
        if len(found_soup) <1: #second html
            sub_soup = soup.find_all("div", id="m")[0]
        if len(found_soup) <1: #if not belong to any format, just take the whole HTML for parsing
            sub_soup = soup
        if sub_soup == None:
            sub_soup = found_soup[0]
            # print(str(sub_soup))
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        next_refs = self.filter_refs(next_refs)
        return sub_soup.text,next_refs
    def filter_refs(self, ref_list):
        ref_list = super().filter_refs(ref_list)
        updated_ref_list = ref_list.copy()
        removed_ref_list = ['https://packetstormsecurity.com/files/tags/exploit', 
                            'https://packetstormsecurity.com/files/tags/arbitrary', 
                            'https://packetstormsecurity.com/files/tags/local',]
        for ref in ref_list:
            if 'packetstormsecurity.com/files/tags' in ref:
                updated_ref_list.remove(ref)
        return updated_ref_list
    
class ListsApacheProcessor(DomainProcessor): #https://lists.apache.org/thread/jsl6dfdgs1mjjo1mbtyflyjr7xftswhc
    def __init__(self, url, products) -> None:
        super().__init__(url, products)
        self.domain = f"https://{get_full_domain(url)}/"
        # print(self.domain)
    @with_timeout(SCRAPING_TIMEOUT)
    def html_parse(self):
        page = requests.get(self.url)
        soup = BeautifulSoup(page.content, "html.parser")
        # description
        sub_soup = None
        found_soup = soup.find_all("pre", {"class": "chatty_body"})
        if len(found_soup) <1: #second html
            sub_soup = soup.find_all("div", {"class": "email_wrapper"})[0]
        if len(found_soup) <1: #if not belong to any format, just take the whole HTML for parsing
            sub_soup = soup
        if sub_soup == None:
            sub_soup = found_soup[0]
            # print(str(sub_soup))
        next_refs = [urljoin(self.domain, a.get('href')) for a in sub_soup.find_all('a') if a.get('href') is not None]
        next_refs = self.filter_refs(next_refs)
        return sub_soup.text,next_refs

if __name__ == "__main__":
    url = "https://access.redhat.com/errata/RHSA-2016:2578.html"
    products= ""
    proc = AccessRedHatProcessor(url, products)
    web_content, next_refs = proc.html_parse()
    # next_refs = ["https://github.com/apache/abc/commit/97a926fb29e7750db0836432615fd86b843edd1e"]
    vfcs = proc.filter_vfc(next_refs,[])
    # print(web_content)
    print(f"next_refs = {next_refs}")
    print(f"vfcs = {vfcs}")