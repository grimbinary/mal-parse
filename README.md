# mal-parse
A helpful malware analysis toolkit made by @grimbinary

-> Overview: 
This Python script is a comprehensive tool designed to automate the process of performing live threat analysis. It integrates with multiple platforms and APIs, including VirusTotal, YARAify, ThreatFox, and Kibana, to provide a holistic view of the threat landscape. The motivation behind this script is to streamline the process of threat analysis, making it more efficient and accessible to security professionals and enthusiasts alike. Check out my other project called 'quickcrowd' to get up and going faster!

-> Features:
VirusTotal API Integration: The script uses the VirusTotal API to fetch threat analysis data for given hashes. This includes the MITRE ATT&CK framework data, providing a detailed view of the tactics, techniques, and procedures (TTPs) used by the threat.

yarGen Integration: yarGen by Florian Roth (@Neo23x0) is a open source tool in the cybersecurity field, designed to assist in the generation of YARA rules for malware detection. It excels in creating rules that are tailored to identify malware families or classes, making it a valuable asset in malware analysis. The strength of yarGen lies in its ability to generate YARA rules based on strings extracted from a set of malware samples. These rules can then be used to identify similar malware in the wild. By integrating yarGen into this script, it enhances our ability to detect and analyze malware, providing a more comprehensive and effective approach to threat hunting.

YARAify Integration: This script leverages YARAify to enhance the analysis of suspicious files and foster a collaborative approach to threat detection with the use of YaraHub.

ThreatFox Integration: ThreatFox is a free threat intelligence platform that provides information about indicators of compromise (IOCs). The script fetches IOCs from ThreatFox related to the analyzed samples, providing additional context to the threat analysis.

Kibana Integration: Kibana is a data visualization tool used for log and time-series analytics. The script can send the threat analysis data to a Kibana instance for visualization, making it easier to understand and interpret the data.

Automated Report Generation: The script generates a detailed report for each analyzed hash, saving it as a text file. This allows for easy review and archiving of threat data.

Platform Integration: The script supports sending the generated reports to either Slack or Discord. This feature enables real-time sharing of threat intelligence with your team.

Preferences File: The script uses a preferences file to store user settings, such as execution preferences and platform details. This makes it easy to reuse the script without having to enter these details each time unless you want to.

Interactive and Non-Interactive Modes: The script supports both interactive and non-interactive modes. In interactive mode, the script prompts the user for inputs. In non-interactive mode, the script uses the preferences file for inputs, allowing it to be used in automated workflows.

Built-in Admin Dashboard: This script will spin up a Python Django dashboard. See README-Dashboard.md. 

-> Motivation:
The inception of this script was motivated by the need for a more efficient and automated approach to threat analysis. By leveraging APIs and integrating with popular communication platforms, this script aims to make threat analysis more accessible and collaborative. The integration with YARAify, ThreatFox, and Kibana further enhances its capabilities, providing a comprehensive tool for open-source threat analysis. The preferences file and the interactive/non-interactive modes add flexibility, making the script adaptable to different use cases and workflows so please adjust it to your needs. 

-> Intended use: 
This script is designed to be ran one to two times per day for optimal results. Regular execution allows for up-to-date threat analysis, ensuring your systems remain informed about the latest malware trends and can respond effectively to potential threats. I ran this from my ~/Documents directory for the sake of ease, please feel free to adjust this part of the script as you like. 

-> Disclaimer:
Please be aware that the 'samples' directory associated with this script contains live, unzipped, Windows-based malware in the exe file format (hence why it was made and tested on a cloud instance running Ubuntu 22.10 - x86_64 - bash 5.2.2). These are explicitly harmful files used for the purpose of threat analysis. Even if you have the necessary expertise in malware analysis, please handle these files with extreme caution. It's important to note that every execution of this script will erase the contents of the samples directory. This is a safety measure designed to prevent the unintentional accumulation and potential misuse of harmful files. Always ensure that any valuable data is backed up or moved from the samples directory before running the script. This script is intended for use by trained professionals in a controlled environment. The author of this script bears no responsibility for any damage or loss caused by the misuse of the files in the samples directory or the script itself. By using this program, you acknowledge that you are taking the risk of being exposed to dangerous software.
