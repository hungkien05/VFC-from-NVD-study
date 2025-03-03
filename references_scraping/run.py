import os,sys,pickle
sys.path.append('..')
import re,math 
import pandas as pd
from config import *
import tldextract
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from html_parse import *
from inner_lib import *
# from ... import lib as parent_lib
from lib import get_repo_by_cpe_product_name, DatabaseConnection, check_if_keyword_exist_in_file

check_scrape = False
domain_counter = dict()
vfc_domain_counter = dict()

pickle_dir = "/home/huuhungn/nvd/references_scraping/pickle"
domain_counter_pickle_path = f'{pickle_dir}/domain_counter_full_domain.pickle'
vfc_domain_counter_pickle_path = f'{pickle_dir}/vfc_domain_counter_full_domain.pickle'
with open(domain_counter_pickle_path, 'rb') as handle:
    domain_counter = pickle.load(handle)
with open(vfc_domain_counter_pickle_path, 'rb') as handle:
    vfc_domain_counter = pickle.load(handle)
count=0
count_scrape = 0

with open('../nvd_cve_all_api/all.json', 'r') as f: 
    cve_data = json.load(f)
cpe_connection = DatabaseConnection("../side_data/titan_wp1b.db")
def extract_domain(url):
    try:
        extracted = tldextract.extract(url)
        return "{}.{}".format(extracted.domain, extracted.suffix) if extracted.suffix else extracted.domain
    except Exception as e:
        print(f"Error extracting domain from {url}: {e}")
        return None
    
def get_full_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def count_domain(domain, is_write_cycle):
    global domain_counter
    if domain in domain_counter:
        domain_counter[domain] +=1
    else:
        domain_counter[domain] =1
        
    if not is_write_cycle:
        return
    with open(domain_counter_pickle_path, 'wb') as handle:
        pickle.dump(domain_counter, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return

def count_vfc_domain(domain,len_vfc,is_write_cycle):
    global vfc_domain_counter
    if domain in vfc_domain_counter:
        vfc_domain_counter[domain] +=len_vfc
    else:
        vfc_domain_counter[domain] = len_vfc
        
    if not is_write_cycle:
        return
    
    with open(vfc_domain_counter_pickle_path, 'wb') as handle:
        pickle.dump(vfc_domain_counter, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return

def mine_web(url,product,depth):
    vfcs = []
    domain = get_full_domain(url)
    proc = None
    global count_scrape
    count_scrape+=1
    if count_scrape%10 ==0:
        is_write_cycle = True
    else:
        is_write_cycle = False
    count_domain(domain, is_write_cycle)
        
    
    if domain == "openwall.com":
        proc = OpenwallProcessor(url, product)
    elif domain == "ubuntu.com":
        proc = UbuntuProcessor(url, product)
    elif "bugzilla.redhat.com" in url:
        proc = BugzillaRedHatProcessor(url, product)
    elif "security.gentoo.org" in url:
        proc = SecurityGentooProcessor(url, product)
    elif "lists.opensuse.org" in url:
        proc = OpensuseProcessor(url, product)
    elif "lists.fedoraproject.org" in url:
        proc = FedoraProjectProcessor(url, product)
    elif "lists.debian.org" in url:
        proc = DebianProcessor(url, product)
    elif "marc.info" in url:
        proc = MarcInfoProcessor(url, product)
    elif "packetstormsecurity.com" in url:
        proc = PacketStormProcessor(url, product)
    elif "oracle.com" in url:
        proc = PacketStormProcessor(url, product)
    # elif depth == MAX_DEPTH:
    #     proc = OtherProcessor(url, product)
    check_other = False
    if proc == None:
        check_other = True
        #choose to explore other website or just top-10 ?
        proc = OtherProcessor(url, product)
        # return [] 
    print(f"Scraping: {url}")
    check_scrape = True
    try:
        web_content, next_refs = proc.html_parse()
        repo_list = repo.split("|")
        vfcs = proc.filter_vfc(next_refs, repo_list)
    except Exception as e:
        print(f"Exception parsing: {e}")
    if len(vfcs) <1 and depth < MAX_DEPTH and check_other == False:
        for ref in next_refs:
            vfcs = [*vfcs, *mine_web(ref,product, depth+1)]
    if len(vfcs) >10:
        return []
    count_vfc_domain(domain,len(vfcs), is_write_cycle)
    return vfcs


def get_git_link_from_cve(cve_id):
    
    for cve in cve_data:
        if cve_id == cve["cve"]["id"]:
            product_names = set()
            for config in cve["cve"]["configurations"]:
                if "nodes" not in config: # nvd cve not full information
                    continue
                for node in config["nodes"]:
                    if "cpeMatch" not in node:
                        continue
                    for match in node["cpeMatch"]:
                        if match["vulnerable"] != True:
                            continue
                        cpe = match["criteria"]
                        try:
                            product_names.add(cpe.split(":")[4])
                        except Exception:
                            print(f"Cannot split ':' for cpe_match: {cpe}")
            break
    repo_list = get_repo_by_cpe_product_name(product_names,cpe_connection.get_instance())
    return repo_list

if __name__ == "__main__":
    
    df = pd.read_csv(NVD_DATA_PATH)
    df.dropna(subset=['reference'], inplace=True)
    # f = open(OUTPUT_LIVE_PATH, "a")
    count =0
    count_scrape = 0
    
    for index, row in df.iterrows():
        refs = row["reference"].split("\n")
        cve_id = row["cve_id"]
        if check_if_keyword_exist_in_file("../side_data/vfc_cve_id.txt", cve_id):
            continue
        year = int(cve_id.split("-")[1])
        # if year <2013:
        #     continue
        count +=1
        # if cve_id !="CVE-2017-2591":
        #     continue
        if count <120000:
            continue
        # if count >82469:
        #     break
        check_scrape = False
        print(f"{count}: {cve_id}")
        product = row["product"]
        repo = row["repo"]
        if pd.isnull(product):
            product = ""
        if pd.isnull(repo):
            repo = ""
        total_vfc = []
        refs_map = []
        for ref in refs:
            if len(ref) <1:
                continue
            vfcs = mine_web(ref,product, depth=1)
            if len(vfcs) >0:
                total_vfc = [*total_vfc, *vfcs]
                vfc_refs = [ref]*len(vfcs)
                refs_map = [*refs_map, *vfc_refs]
        if check_scrape:
            count_scrape +=1
        #output to file
        
        if len(total_vfc) >0:
            print(f"VFC found")
            # f.write(f"{cve_id}\n")
            # for vfc in total_vfc:
            #     f.write(f"{vfc}\n")
            output_data = {
                "cve_id": cve_id,
                "patch_url": total_vfc,
                "refs_mapping": refs_map,
            }
            dump_jsonl_mono(output_data,OUTPUT_LIVE_PATH)

    print(f"count_scrape = {count_scrape}")
    cpe_connection.close_connection()