<div align="left">by liav tausi</div>
<div align="center">
    <img src="https://user-images.githubusercontent.com/50721644/212086526-2fdd00bb-057d-44b5-afcf-9143c1dd78af.png">
    <h2 align="center">virustotal automator</h2>
</div>







This program is a **CLI** running scanner that allows users to scan multiple **files and URLs** for potential malware and viruses. It utilizes the **VirusTotal** database API and retrieve scan results and reputation scores for the given files or URLs.

### *VTAutomator* 
serves as the base class for the other classes and contains common functionality such as endpoints data, cache handling, and error handling.

### *VTFile*
used for scanning files. It inherits from the VTAutomator class and includes additional functionality specific to analysing multiple files, such as the ability to upload multiple files to the VirusTotal servers for scanning and retrieve the scan results.

### *VTUrl*
used for scanning URLs. It also inherits from the VTAutomator class and includes additional functionality specific to scanning multiple URLs, such as the ability to submit multiple URLs for scanning and retrieve the scan results.

### *CLI*
```bash
[-h] [--workers WORKERS] (--file FILE [FILE ...] | --password PASSWORD | --url URL [URL ...]) type method [vt_key]
```

**type**:  This argument is used to specify the type of scan, either 'file' or 'url'.

**workers**:  This argument is used to specify the number of worker threads to use in the scan.

**method**:  This argument is used to specify the method of scan, such as **get_file** **,** **get_files** **,** **post_file** **,**
**post_files** **,** **post_get_file** **,** **post_get_files** **,** **get_url** **,** **get_urls** **,** **post_url** **,** **post_urls** **,** **post_get_url** **,** **post_get_urls**

**vt_key**:  This argument is used to specify the VirusTotal API key.

**file**:  This argument is used to specify a list of file paths to scan.

**password**:  This argument is used to specify an optional file password for files that have been password protected.

**url**:  This argument is used to specify a list of URLs to scan.


```bash
The program will take in url/s or file/s as input and return the scan results from the VirusTotal database

positional arguments:
  type                  type of scan (file or url)
  method                method to run
  vt_key                VirusTotal API key

options:
  -h, --help            show this help message and exit
  --workers WORKERS     number of workers
  --file FILE [FILE ...]
                        a list of files
  --password PASSWORD   optional file password
  --url URL [URL ...]   a list of URLs
  ```



