import json
def get_api_key():
    with open(r'', 'r') as fh:
       read = json.load(fh)
       api_key = read["api_keys"]["VirusTotal"]["key_one"]
       return api_key
