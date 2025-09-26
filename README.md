# 🧅 Security Onion LLM Alert Triage

An automated alert triage system that uses LLMs to analyze and classify security alerts from Security Onion by enriching them with contextual data from Zeek logs.

---

## 📋 Table of Contents

* [About](#-about)
* [Architecture](#-architecture)
* [Key Features](#-key-features)
* [Built With](#️-built-with)
* [Getting Started](#-getting-started)
    * [Prerequisites](#prerequisites)
    * [Installation](#installation)
    * [Configuration](#configuration)
* [Usage](#-usage)
* [Demo](#-demo)
---

## 🧐 About

This project enhances Security Onion's alert monitoring capabilities by:

* Collecting and enriching alerts with relevant Zeek log context.
* Using LLMs to analyze alerts and evidence to determine true/false positives.
* Providing a real-time dashboard for alert monitoring and triage.
* Supporting ground truth validation workflows.

---

## 🏗️ Architecture

The project directory is structured as follows:
```sh
├── collectors/       # Zeek log collectors (conn, dns, http, etc)
├── scripts/          # Helper scripts for data collection
├── so_alerts/        # Raw alert storage
├── so_logs/          # Zeek log storage
├── ground_truth/     # Ground truth validation scripts
├── outputs/          # Enriched alerts and analysis results
└── llm_model/        # Local LLM model files
```


---

## ✨ Key Features

* **Real-time Monitoring**: Continuously monitors and enriches alerts as they arrive.
* **Contextual Evidence**: Automatically collects relevant evidence from Zeek logs.
* **LLM-based Analysis**: Leverages Large Language Models for intelligent alert classification.
* **Interactive Dashboard**: A user-friendly Streamlit interface for triage.
* **Ground Truth Validation**: A framework to validate the model's accuracy.
* **Flexible Inference**: Supports both local (via `Llama.cpp`) and remote LLM APIs.

---

## 🛠️ Built With

* [Python](https://www.python.org/)
* [Streamlit](https://streamlit.io/)
* [Llama.cpp](https://github.com/ggerganov/llama.cpp)
* [Elasticsearch](https://www.elastic.co/)
* [Security Onion (Zeek/Suricata)](https://securityonionsolutions.com/)
* [Pandas](https://pandas.pydata.org/)
* [Paramiko](http://www.paramiko.org/)

---

## 🚀 Getting Started

Follow these instructions to get a copy of the project up and running on your local machine.

### Prerequisites

* Python 3.10+
* A running Security Onion 2.3+ deployment
* SSH access to the Security Onion server
* Elasticsearch access credentials

### Installation

1.  **Clone the repository**
    ```sh
    git clone <repo-url>
    cd security_onion_llm_project
    ```

2.  **Install dependencies**
    ```sh
    pip install -r requirements.txt
    ```

3.  **Create your configuration file**
    ```sh
    cp scripts/config_template.py config.py
    ```

### Configuration

1.  Update `config.py` with your Security Onion and Elasticsearch details:
    ```python
    # config.py
    REMOTE_USERNAME = 'soc_admin'
    REMOTE_HOST = 'your-so-ip'
    ELASTIC_USER = 'your-elastic-user'
    ELASTIC_PASS = 'your-elastic-pass' 
    ```

2.  Configure your LLM settings in `llm_client.py`. You can choose between a remote API or a local model.
    ```python
    # llm_client.py
    USE_REMOTE = True # Set to False to use a local model
    
    # --- Remote API Settings ---
    REMOTE_API_URL = "your-api-endpoint"

    # --- Local Model Settings ---
    LOCAL_MODEL_NAME = "path/to/local/model"
    ```

---

## 🖥️ Usage

1.  **Start Log Collection**

    These scripts run in the background to gather Zeek logs from your Security Onion manager via SSH.
    ```sh
    cd scripts
    ./start_scripts.sh
    ```

2.  **Choose Alert Sync Mode**

    When you start the dashboard, you will be prompted to choose how to sync alerts:
    * **Full Alerts in Day**: Fetches all alerts from the beginning of the current day.
    * **New Alerts in Day**: Fetches only new alerts that have not been seen since the script started.

3.  **Launch the Dashboard**
    ```sh
    streamlit run dashboard.py
    ```

4.  **Monitor Alerts**

    Use the dashboard interface to monitor incoming alerts, view enriched context, and see the LLM's analysis in real-time.

## 👁️ Demo  

> 🎥 [Click để xem bản demo](https://drive.google.com/file/d/1xAk7FiyEp3_8gRovNPe0rnZ5C2pYLWTn/view?usp=sharing)
