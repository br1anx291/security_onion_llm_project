Security Onion LLM Alert Triage
An automated alert triage system that uses LLMs to analyze and classify security alerts from Security Onion by enriching them with contextual data from Zeek logs.

Table of Contents
About
Architecture
Key Features
Built With
Getting Started
Prerequisites
Installation
Configuration
Usage


About
This project enhances Security Onion's alert monitoring capabilities by:

Collecting and enriching alerts with relevant Zeek log context
Using LLMs to analyze alerts and evidence to determine true/false positives
Providing a real-time dashboard for alert monitoring and triage
Supporting ground truth validation workflows

Architecture
├── collectors/         # Zeek log collectors (conn, dns, http, etc)
├── scripts/           # Helper scripts for data collection
├── so_alerts/        # Raw alert storage
├── so_logs/          # Zeek log storage  
├── ground_truth/     # Ground truth validation scripts
├── outputs/          # Enriched alerts and analysis results
└── llm_model/        # Local LLM model files

Key Features
Real-time alert monitoring and enrichment
Contextual evidence collection from Zeek logs
LLM-based alert analysis and classification
Interactive Streamlit dashboard
Ground truth validation framework
Support for both local and remote LLM inference

Built With
Python
Streamlit
Llama.cpp
Elasticsearch
Security Onion (Zeek/Suricata)
Pandas
Paramiko (SSH/SFTP)

Getting Started
Prerequisites
Python 3.10+
Security Onion 2.3+ deployment
SSH access to Security Onion server
Elasticsearch access credentials

Installation
Clone the repository
git clone <repo-url>
cd security_onion_llm_project

Install dependencies
pip install -r requirements.txt

Copy configuration template
cp scripts/config_template.py config.py

Configuration
Update config.py with your Security Onion details:
REMOTE_USERNAME = 'soc_admin'
REMOTE_HOST = 'your-so-ip'
ELASTIC_USER = 'your-elastic-user'
ELASTIC_PASS = 'your-elastic-pass' 

Configure LLM settings in llm_client.py:
USE_REMOTE = True # Use remote or local inference
REMOTE_API_URL = "your-api-endpoint"
LOCAL_MODEL_NAME = "path/to/local/model"

Usage
Start log collection:
cd scripts
./start_scripts.sh

Launch the dashboard:
streamlit run dashboard.py