# mal-parse
A helpful malware analysis toolkit made by @grimbinary. Simply install the requirements, update the preferences.conf with your unique preferences, and run with 'python3 mal-parse.py -h' 

# Overview: 
This Python script is a comprehensive tool designed to automate the process of performing live threat analysis on 100 Windows-based malware samples (can be modified to ingest and process linux malware, too). It integrates with multiple platforms and APIs, including VirusTotal, YARAify, ThreatFox, and Elasticsearch, to provide a holistic view of the threats lingering within the samples. Make sure to check out my other repo called 'quickcrowd' to get up and going faster!

# Features:
-> VirusTotal API Integration (required): The script uses the VirusTotal API to fetch threat analysis data for given hashes. This involves using its the MITRE ATT&CK framework data, to provide you with a detailed view of the tactics, techniques, and procedures (TTPs) used by the threats. You can get this API key for free, although the limit requests will be capped unless you get premium. 

-> yarGen Integration: yarGen by Florian Roth (@Neo23x0) is a open source tool in the cybersecurity field, designed to assist in the generation of YARA rules for malware detection. It excels in creating rules that are tailored to identify malware families or classes, making it a valuable asset in malware analysis. The strength of yarGen lies in its ability to generate YARA rules based on strings extracted from a set of malware samples. These rules can then be used to identify similar malware in the wild. By integrating yarGen into this script, it enhances our ability to detect and analyze malware, providing a more comprehensive and effective approach to threat hunting.

-> YARAify Integration: This script leverages YARAify to enhance the analysis of suspicious files and foster a collaborative approach to threat detection with the use of YaraHub.

-> ThreatFox Integration: ThreatFox is a free threat intelligence platform that provides information about indicators of compromise (IOCs). The script fetches IOCs from ThreatFox related to the analyzed samples, providing additional context to the threat analysis.

-> Elasticsearch Transmission: Elasticsearch is a search and analytics engine, while Kibana is a data visualization tool used for visually interpreting said analytics. The script will send the threat analysis data to your Elasticsearch IP and port, making it easier to understand and interpret the data using Kibana. 

-> Automated Report Generation: The script generates a detailed report for each analyzed hash, saving it as a text file. This allows for easy review and archiving of threat data.

-> Platform Integration: The script supports sending the generated reports to either Slack or Discord. This feature enables real-time sharing of threat intelligence with your team.

-> Interactive and Non-Interactive Modes: The script supports both interactive and non-interactive modes. In interactive mode, the script prompts the user for inputs. In non-interactive mode, the script uses the preferences file for inputs, allowing it to be used in automated workflows.

-> Built-in Admin Dashboard: This script will spin up a lightweight Python Django dashboard that allows for visual analysis and ATT&CK mappings. See README-Dashboard.md if you want to use it. 

# Motivation:
The inception of this script was motivated by the need for a more user-friendly, efficient, and automated approach to threat analysis. By leveraging APIs and integrating with popular communication platforms, this script aims to make threat analysis more accessible and collaborative. The integration with YARAify, ThreatFox, and Elasticsearch further enhances its capabilities, providing a comprehensive tool for open-source threat analysis. The preferences file and the interactive/non-interactive modes add flexibility, making the script adaptable to different use cases and workflows so please adjust it to your needs. 

# Disclaimer:
Please be aware that the 'samples' directory associated with this script contains live, unzipped, Windows-based malware in the exe file format (hence why it was made and tested on a cloud instance running Ubuntu 22.10 - x86_64 - bash 5.2.2). These are explicitly harmful files used for the purpose of threat analysis. Even if you have the necessary expertise in malware analysis, please handle these files with extreme caution. It is important to note that every execution of this script will erase the contents of the samples directory. This is a safety measure designed to prevent the unintentional accumulation and potential misuse of harmful files. Always ensure that any valuable data is backed up or moved from the samples directory before running the script. This script is intended for use by trained professionals in a controlled environment. The author of this script bears no responsibility for any damage or loss caused by the misuse of the files in the samples directory or the script itself. By using this program, you acknowledge that you are taking the risk of being exposed to dangerous software.
