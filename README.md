# virustotal_automator
This program is a **CLI** running scanner that allows users to scan multiple **files and URLs** for potential malware and viruses. It utilizes the **VirusTotal** database API and to retrieve scan results and reputation scores for the given files or URLs.

### VTAutomator
serves as the base class for the other classes and contains common functionality such as endpoints data, cache handling, and error handling.

### VTFile
used for scanning files. It inherits from the VTAutomator class and includes additional functionality specific to analysing multiple files, such as the ability to upload multiple files to the VirusTotal servers for scanning and retrieve the scan results.

### VTUrl
used for scanning URLs. It also inherits from the VTAutomator class and includes additional functionality specific to scanning multiple URLs, such as the ability to submit multiple URLs for scanning and retrieve the scan results.

### CLI 
![image](https://user-images.githubusercontent.com/50721644/212075029-23bac03b-0d6b-482f-9da4-75a319d18cd8.png)

**type**:  This argument is used to specify the type of scan, either 'file' or 'url'.

**workers**:  This argument is used to specify the number of worker threads to use in the scan.

**method**:  This argument is used to specify the method of scan, such as **get_file** **,** **post_file** **,** 
**post_get_file** **,** **get_url** **,** **post_url** **,** **post_get_url**

**vt_key**:  This argument is used to specify the VirusTotal API key.

**file**:  This argument is used to specify a list of file paths to scan.

**password**:  This argument is used to specify an optional file password for files that have been password protected.

**url**:  This argument is used to specify a list of URLs to scan.

![Screenshot_20230112_151027](https://user-images.githubusercontent.com/50721644/212075085-f5cbfe88-64ea-4646-9e13-d6236d09f5eb.png)



