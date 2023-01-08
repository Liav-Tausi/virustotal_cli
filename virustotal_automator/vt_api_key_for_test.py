import json

with open(r'C:\Users\liavt\Documents\api_keys\all_api_keys.json', 'r') as fh:
    vt: dict = json.load(fh)
    vt_key: str = vt["api_keys"]["VirusTotal"]