Unified Web & Cloud Misconfiguration Detection Suite


A modular, automated CLI-based security tool for detecting high-risk misconfigurations in modern web applications and cloud environments.

Developed as part of an MSc Cybersecurity Practicum, this tool integrates multiple scanners into a single unified automation suite.

📌 Key Capabilities

🔍 Detects CORS misconfigurations

☁️ Identifies public or exposed S3 buckets

🔐 Analyzes OAuth 2.0 / OIDC vulnerabilities

⚡ Lightweight and fast

🛡️ Non-destructive testing

🖥️ Unified CLI interface




🧱 System Architecture
                ┌──────────────────────────────┐
                │  Unified CLI Tool            │
                │  (web_suite_fin.py)          │
                └────────────┬─────────────────┘
                             │
     ┌───────────────────────┼────────────────────────┐
     │                       │                        │
┌──────────────┐     ┌──────────────┐        ┌──────────────┐
│ CORS Scanner │     │ S3 Scanner   │        │ OAuth Scanner│
│ (cors.py)    │     │ (dsb.py)     │        │ (oauth...)   │
└──────────────┘     └──────────────┘        └──────────────┘









📁 Project Structure
.
├── cors.py                  # CORS misconfiguration scanner
├── dsb.py                   # S3 bucket scanner
├── oauth_vuln_scanner.py    # OAuth/OIDC scanner
├── web_suite_fin.py         # Unified CLI automation tool
├── requirements.txt         # Python dependencies
└── README.md
⚙️ Requirements
🖥️ Recommended Environment

OS: Linux / Kali Linux

Python: 3.x

RAM: 8GB+ (16GB recommended)

CPU: 4 cores

🛠️ Installation
1. Clone the repository
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
2. Create virtual environment
python3 -m venv venv
3. Activate virtual environment
source venv/bin/activate
4. Install dependencies
pip install -r requirements.txt
▶️ Usage

Run the unified scanner:

python3 web_suite_fin.py
🔄 How It Works

Launch the CLI tool

Select a scan type:

CORS Scan

S3 Bucket Scan

OAuth/OIDC Scan

Provide the target (URL or bucket name)

The selected module executes

Results are displayed in structured format

🧪 Scanner Modules
🌐 CORS Scanner (cors.py)

Detects:

Wildcard (*) origins

Reflected origin vulnerabilities

Credential misconfigurations

Missing or insecure headers

☁️ S3 Bucket Scanner (dsb.py)

Performs:

Public read access checks

Public write access testing

Bucket listing validation

🔐 OAuth/OIDC Scanner (oauth_vuln_scanner.py)

Analyzes:

OpenID configuration endpoints

Missing PKCE protection

Insecure HTTP usage

Token leakage in JavaScript

Hardcoded credentials

📊 Output

Clean CLI output using rich

Structured tables for readability

Clear identification of vulnerabilities

⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Do NOT use it on systems without proper permission.
