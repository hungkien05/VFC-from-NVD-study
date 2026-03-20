from unidiff import PatchSet
import os
from patch_parser import process_function

# PLATFORM = "github"
count_java_func =0
count =0
# directory_path = None
# passed_function_save_dir = None

def get_functions(directory_path,passed_function_save_dir, platform):
    global count,count_java_func
    count_java_func=0
    for filename in os.listdir(directory_path):
        count+=1
        print(count)
        # if count<=3225:
        #     continue
        # if count>10:
        #     break
        cve_id = filename.split(".")[0]
        file_path = os.path.join(directory_path, filename)
        # if "CVE-2023-29206" not in filename:
        #     continue

        patch_set = None
        if not os.path.isfile(file_path):
            continue
        count_java_func += process_function(file_path,platform, passed_function_save_dir)
        # break
        # if count_java_func >10:
        #     break
        
    print(count_java_func)
    
if __name__ == "__main__":
    # main()
    
    for platform in ["github", 
                     "gitlab", "bitbucket"
                     ]:
        directory_path = f"crawled_patch/{platform}"
        passed_function_save_dir = f"functions/140824/{platform}"
        os.makedirs(passed_function_save_dir, exist_ok=True)
        get_functions( directory_path,passed_function_save_dir,platform)
        # break