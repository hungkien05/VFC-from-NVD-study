import requests
from urllib.parse import urljoin, urlparse
import time
import pandas as pd
import numpy as np
import ast
from bs4 import BeautifulSoup
import re,sys,os

from scraper import *
sys.path.append('./')
from config import SCRAPING_TIMEOUT, NVD_IMPLICIT_DATA_PATH, OUTPUT_LIVE_PATH_A
from inner_lib import get_full_domain, with_timeout, dump_jsonl_mono



if __name__ == "__main__":
    df = pd.read_csv(NVD_IMPLICIT_DATA_PATH)
    df.dropna(subset=['reference'], inplace=True)
    # f = open(OUTPUT_LIVE_PATH, "a")
    count =0
    count_scrape = 0
    
    for index, row in df.iterrows():
        refs = row["reference"].split("\n")
        cve_id = row["cve_id"]
        year = int(cve_id.split("-")[1])
        # if year <2013:
        #     continue
        count +=1
        if cve_id !="CVE-2022-36537":
            continue
        if count <21124:
            continue
        # if count >200000:
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
        
        #direction A start with Snyk.io
        scraper = GithubAdvisoriesScraper(cve_id, product)
        vfcs=  scraper.search_vfc()
        if len(vfcs) >0:
            total_vfc = [*total_vfc, *vfcs]
        
        #end snyk.io
        
        if len(total_vfc) >0:
            print(f"VFC found")
            # f.write(f"{cve_id}\n")
            # for vfc in total_vfc:
            #     f.write(f"{vfc}\n")
            output_data = {
                "cve_id": cve_id,
                "patch_url": total_vfc,
                # "refs_mapping": refs_map,
            }
            dump_jsonl_mono(output_data,OUTPUT_LIVE_PATH_A)

    print(f"count_scrape = {count_scrape}")
    # cpe_connection.close_connection()