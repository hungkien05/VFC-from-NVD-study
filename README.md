# Mapping NVD Records to Their VFCs: How Hard is it?

Replication package of the paper "Mapping NVD Records to Their VFCs: How Hard is it?"

## Dataset
- Automatically collected VFCs can be found at ```dataset/auto```
- Details of manual study can be found at ```dataset/manual```

## Replicate 

### 1. Install requirement
```pip install -r requirements```
### 2. Collect VFCs from Patch-tagged NVD entries
```python nvd_api_monitor.py```
### 3. Collect VFCs from Non-Patch-tagged NVD entries using NVD references
``` 
cd references_scraping
python run.py
```

### 4. Collect VFCs from Non-Patch-tagged NVD entries using external resource
``` 
cd references_scraping/external_resource
python main.py
```