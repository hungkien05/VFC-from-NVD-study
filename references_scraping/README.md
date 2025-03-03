# Data Collection

### This folder contains all scripts used to perform web scraping on top 12 domains found in references. 
- Any reference that is tied to any of the 12 domains are scraped, regardless of which page the reference refers to.

### Data Collection Contains:
1. OUT.csv
    - Initial dataset with CVE_ID, NVD description, and references

2. domains 1-6 folder contains a single compiled web scraping script (Crawling Scripts.ipynb) for the first 6 domains. Scraped features for each domain are saved as npy files
    - Crawling Scripts.ipynb: Notebook containing web scraping code for domains (redhat, opensuse, oracle, bugzilla redhat, debian, lists.debian)
    - .npy files: Store output dictionaries of scraped features per domain

3. domains 7-14 folder contains individual folders with web scraping scripts for each particular domain (name of folder represents domain name). Scraped features for each domain are saved as pickle files.
    - 8 folders: each folder with notebook containing web scraping code for one domain (bugs_launchpad, fedora, github, openwall, security_gentoo, securitytracker, ubuntu, usn.ubuntu)
    - Each folder contains .pkl files which stores outputs of text scraped per domain

4. all_data_combination folder contains scripts to combine all scraped data with original NVD dataset
    - Due to the nature of references, some references may require us to capture the text in different formats
    - combination.ipynb manually takes in each .pkl file or .npy file and joins it with its corresponding CVE in OUT.csv file
    - Outputs new csv file as processed_references.csv
