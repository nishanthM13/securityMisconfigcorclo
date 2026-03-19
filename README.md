Unified web & CLoud Misconfiguration Scanner
---------------------------------------------

A lightweight, non-destructive command-line tool for detcting high-risk misconfigurations in CORS, S# buckets and OAUTH/OIDC implementations.
This project was developed as part of the MSc Cybersecurity Research practicum.

Note: all the code file should be in one folder
|__ vuln_app.py             # vulnerable application to test
├── cors.py                 # CORS Misconfiguration Scanner
├── dsb.py                  # S3 Bucket Misconfiguration Scanner
├── oauth_vuln_scanner.py   # OAuth/OIDC Scanner
├── web_suite_fin.py        # Unified CLI Tool
├── requirements.txt
└── README.md 
-----------------------------------------------
To run this code

1)create a venv
python3 -m venv venv

2)activate venv
source venv/bin/activate

3)cd to the directory file
example:
cd thesis/finalTool

4)run the code
python3 web_suite_fin.py
