# 🐝 BeezPCAP – AI-Enhanced PCAP Threat Intelligence

**BeezPCAP** is an automated packet capture (PCAP) analysis tool built with Python. It leverages `Suricata` and `Zeek` to extract network insights, enriches indicators of compromise (IOCs) using **VirusTotal** and **AbuseIPDB**, and generates a detailed HTML report. It optionally summarizes key threats using a local **AI model via Ollama**.


## 🔧 Features

- 🚨 Extracts alerts and indicators from Suricata & Zeek
- 🔐 Enriches IPs and file hashes with VirusTotal & AbuseIPDB
- 🧠 Generates an AI-powered summary via Mistral (Ollama)
- 📄 Produces a clean, readable HTML report
- 🛠 Caches enrichment results locally to avoid repeat API calls
- 📁 Supports Dockerized Zeek and Suricata processing


## 📦 Requirements

Install dependencies into a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
````

Required tools (installed separately):

* [Docker](https://docs.docker.com/get-docker/) (used for Suricata and Zeek)
* [Ollama](https://ollama.com/) with Mistral model (optional, for AI summary)

---

## 🔐 Environment Variables

Create a `.env` file in the project root with the following:

```env
VT_API_KEY=your_virustotal_api_key
ABUSE_API_KEY=your_abuseipdb_api_key
AIMODULE=OLLAMA   # or set to DISABLE to skip AI summary
REPORT_FORMAT=pdf
```

---

## 🚀 Usage

To analyze a PCAP file and generate a report:

```bash
python3 beezpcap.py yourfile.pcap
```

The report will be saved in the `reports/` folder.

---

## 📁 Output Structure

```
reports/
├── report_<name>_<timestamp>.html/pdf    ← Final report
output/
├── <pcap_name_timestamp>/            ← Zeek & Suricata logs
ioc_cache.json                         ← IOC enrichment cache
summary_prompt.txt                     ← AI prompt used for Mistral
```

---

## 📚 Notes

* Free VirusTotal accounts allow 4 lookups/min and 500/day.
* AbuseIPDB free tier allows 1000 queries/day.
* Only **public IPs** are enriched; private/internal addresses are ignored.
* AI summaries run using `ollama run mistral` and may timeout if the model is large or slow to start.

---

## 🤖 Optional Enhancements

* Replace Ollama with OpenAI GPT if needed.
* Extend IOC checks to domains and file names.
* Add PDF export for reports.

---

## 🛡 Disclaimer

This tool is intended for **research and internal threat hunting** only. Use responsibly and respect API terms of service.

---

## 🧑‍💻 Author

Built with ❤️ by \[bishesh910]. I used ChatGPT to create this README file.

