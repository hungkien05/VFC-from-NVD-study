import pickle
from urllib.parse import urlparse
import os,json,re
import threading
def get_full_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain



class TimeoutException(Exception):
    pass

def with_timeout(timeout):
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]

            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target)
            thread.start()
            thread.join(timeout)
            if thread.is_alive():
                raise TimeoutException("Timed out !")
            if exception[0]:
                raise exception[0]
            return result[0]
        return wrapper
    return decorator

# Example usage
# @with_timeout(120)  # Timeout set to 2 minutes (120 seconds)
# def long_running_function():
#     import time
#     print("Function started")
#     time.sleep(180)  # Simulating long-running process
#     print("Function ended")
#     return "Completed"

# try:
#     result = long_running_function()
#     print(result)
# except TimeoutException as e:
#     print(e)
# except Exception as e:
#     print("An error occurred:", e)

def create_file_if_not_exists(filename):
    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            pass  # This is a no-op, just creating an empty file
def dump_jsonl_mono(data, filename):
    create_file_if_not_exists(filename)
    with open(filename, 'a') as f:
        json.dump(data, f)
        f.write(',\n')
        
        
def dump_pickle(obj, path):
    with open(path, 'wb') as handle:
        pickle.dump(obj, handle, protocol=pickle.HIGHEST_PROTOCOL)
        
def read_pickle(path):
    with open(path, 'rb') as handle:
        return pickle.load(handle)
    


def is_non_alphanumeric(s):
    # Match only non-alphanumeric characters
    return bool(re.match(r'^[^a-zA-Z0-9]+$', s))

def remove_non_alphanumeric(s):
    # Substitute all non-alphanumeric characters with an empty string
    return re.sub(r'[^a-zA-Z0-9-_,\s]', '', s)
