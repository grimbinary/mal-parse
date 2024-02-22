# __   __  _______  ___             _______  _______  ______    _______  _______ 
#|  |_|  ||   _   ||   |           |       ||   _   ||    _ |  |       ||       |
#|       ||  |_|  ||   |     ____  |    _  ||  |_|  ||   | ||  |  _____||    ___|
#|       ||       ||   |    |____| |   |_| ||       ||   |_||_ | |_____ |   |___ 
#|       ||       ||   |___        |    ___||       ||    __  ||_____  ||    ___|
#| ||_|| ||   _   ||       |       |   |    |   _   ||   |  | | _____| ||   |___ 
#|_|   |_||__| |__||_______|       |___|    |__| |__||___|  |_||_______||_______|

#####################################################################################################################
# Author: Grim : @grimbinary                                                                                        #
# Date: 2024-02-21                                                                                                  # 
# Purpose: To make open source malware detection and analysis portarable and easy                                   #
# To Do:                                                                                                            #
# Integrate malware sandbox engine                                                                                  #   
#                                                                                                                   #
#####################################################################################################################

import os
import subprocess
import time
import zipfile
from colorama import Fore
import requests
import argparse
import json
import pyzipper
import urllib3
import openai
import shutil
import re
import hashlib
import uuid
import sys
import signal
from halo import Halo
from tqdm import tqdm
import configparser
from datetime import datetime
from subprocess import run
from elasticsearch import Elasticsearch
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from discord_webhook import DiscordWebhook


gold = Fore.YELLOW
green = Fore.GREEN
white = Fore.WHITE

#init
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mal-Parse: the helpful malware analysis toolkit.")
    parser.add_argument('--non-interactive', action='store_true', help='run the script in non-interactive mode by reading off the settings stored in the preferences.conf file')

    args = parser.parse_args()

    config = configparser.ConfigParser()

    config.read('preferences.conf')

if args.non_interactive:
    interactive_mode = False
    print("Running in non-interactive mode due to --non-interactive argument.")
else:
    interactive_mode = config.getboolean('Preferences', 'interactive_mode', fallback=True)
    print(f"Interactive mode setting from preferences.conf: {interactive_mode}")
    if interactive_mode:
        print("Running in interactive mode.")
    else:
        print("Running in non-interactive mode due to setting in preferences.conf.")


def get_user_choice(prompt):
    while True:
        user_choice = input(prompt)
        if user_choice.lower() in ['y', 'n']:
            return user_choice.lower()
        else:
            print("Not a valid option. Please enter 'y' or 'n'.")

def execute_command(command):
    subprocess.run(command, shell=True)

def execute_quiet_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f'Error executing command: {command}\n{stderr.decode()}')
    else:
        print(stdout.decode())
        return stdout.decode()
    
def create_directory(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)
        print(f"Directory {directory} created.")
    else:
        print(f"Directory {directory} already exists.")

if interactive_mode:
    db_update = get_user_choice("Would you like to update the DB? (y/n) -> ")
    yaraify_transmission_choice = get_user_choice("Would you like to send your YARA rules to YARAify? (y/n) -> ")
    kibana_transmission_choice = get_user_choice("Would you like to send your data to ElasticSearch? (y/n) -> ")
    threatfox_transmission_choice = get_user_choice("Would you like to send your data to ThreatFox? (y/n) -> ")
    threatfox_api_key = input("Please enter your ThreatFox API key: ") if threatfox_transmission_choice.lower() == 'y' else None
    vt_api_key = input("Please enter your VirusTotal API key so that you can receive TTP analysis based on the samples: ")
    ai_analysis_choice = get_user_choice("Would you like to have your malware sample files summarized by AI? (y/n) -> ")
    openai_api_key = input("Please enter your OpenAI API key: ") if ai_analysis_choice.lower() == 'y' else None
    engine_choice_choice = input("Please enter your engine choice (default is 'text-davinci-003 see full list in completions of OpenAI.'): ") if ai_analysis_choice.lower() == 'y' else None
    prompt = input("Please enter your prompt (default is something along the lines of 'Summarize indicators from provided samples data, note patterns, mention prevention methods): ") if ai_analysis_choice.lower() == 'y' else None
    slack_token = None
    slack_channel_id = None
    discord_webhook_url = None
    platform_choice = input("Do you want to send the report? (y/n): -> ").lower()
    if platform_choice == 'y':
        platform = input("Which platform do you want to send the report? (slack/discord): -> ").lower()
        if platform == 'discord':
            discord_webhook_url = input("Please enter your Discord webhook URL: ")
        elif platform == 'slack':
            slack_token = input("Please enter your Slack token: ")
            slack_channel_id = input("Please enter your Slack channel ID: ")
        else:
            print("Ok. Not sending the report.")
else:
    db_update = config.get('Update', 'db_update', fallback='n')
    yaraify_transmission_choice = config.get('YARAify', 'yaraify_transmission', fallback='n')
    kibana_transmission_choice = config.get('Kibana', 'kibana_transmission', fallback='n')
    kibana_ip = config.get('Kibana', 'kibana_ip_address', fallback=None)
    kibana_port = config.get('Kibana', 'kibana_port', fallback=None)
    kibana_file_name = config.get('Kibana', 'kibana_file_name', fallback=None)
    threatfox_transmission_choice = config.get('ThreatFox', 'threatfox_transmission', fallback='n')
    threatfox_api_key = config.get('Threatfox', 'threatfox_api_key', fallback=None)
    vt_api_key = config.get('Virustotal', 'vt_api_key', fallback=None)
    ai_analysis_choice = config.get('OpenAI', 'ai_analysis', fallback='n')
    openai_api_key = config.get('OpenAI', 'openai_api_key', fallback=None)
    engine_choice = config.get('OpenAI', 'engine_choice', fallback=None)
    prompt = config.get('OpenAI', 'prompt', fallback=None)
    platform_choice = config.get('Platform', 'platform_choice', fallback='n').lower()
    if platform_choice == 'y':
        platform = config.get('Platform', 'platform', fallback=None).lower()
        if platform == 'discord':
            discord_webhook_url = config.get('Platform', 'discord_webhook_url', fallback=None)
        elif platform == 'slack':
            slack_token = config.get('Platform', 'slack_token', fallback=None)
            slack_channel_id = config.get('Platform', 'slack_channel_id', fallback=None)

def signal_handler(sig, frame):
        print('KeyboardInterrupt detected. Cancelling script...')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


#Stage 1: Preparation 
print(f"{green}Stage 1/9: Preparing Environment{white}")

print(f"{white}Making room for new samples...{white}")

execute_command('rm ~/mal-parse/malware/hashes.json')
execute_command('rm ~/mal-parse/malware/samples.json')
execute_command('rm ~/mal-parse/malware/yarGen/rules.yar')
execute_command('rm ~/mal-parse/investigate/report.json')
execute_command('rm ~/mal-parse/investigate/formatted_report.json')
execute_command('rm ~/mal-parse/investigate/hashes.json')
execute_command('rm ~/mal-parse/admin/static/threats.json')
execute_command('rm ~/mal-parse/admin/static/new_threats.json')
execute_command('rm ~/mal-parse/admin/static/daily_threats.json')
execute_command('rm ~/mal-parse/admin/static/report.json')
execute_command('rm ~/mal-parse/admin/formatted_report.json')

print(f"{white}Cleaning up...{white}")
execute_command('rm -rf ~/mal-parse/malware/samples/')
execute_command('rm -rf ~/mal-parse/investigate/sample_hashes/')
execute_command('rm -rf ~/mal-parse/investigate/reduced_sample_files/')
execute_command('rm -rf ~/mal-parse/investigate/ai_report/')
execute_command('rm -rf ~/mal-parse/investigate/threat_analysis/')

time.sleep(5)
print(f"{white}Running data processing commands...{white}")
print(f"{white}Please wait...{white}")
time.sleep(5)
create_directory('malware')
create_directory('investigate')

os.chdir('malware/')
os.makedirs("samples", exist_ok=True)

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

url = "https://mb-api.abuse.ch/api/v1/"
data = {"query": "get_file_type", "file_type": "exe", "limit": "100"}
response = requests.post(url, data=data)
with open("hashes.json", "w") as file:
    file.write(response.text)

if os.path.exists("index.html"):
    os.rename("index.html", "hashes.json")

try:
    with open("hashes.json") as file:
        data = json.load(file)
    samples = [{"sha256_hash": item["sha256_hash"]} for item in data["data"]]
    with open("samples.json", "w") as file:
        json.dump(samples, file)
    time.sleep(15)

except json.JSONDecodeError:
    print("An error occurred while decoding the JSON data. Please run the script again.")

# -----------------------------------------------------> END PYTHON3 COMMAND <-------------------------------------------------------------

print(f"{white}Running puller.py with samples.json. Saving malicious files to samples directory{white}")

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

def check_sha256(s):
    if s == "": 
        return
    if len(s) != 64:
        raise ValueError("Please use sha256 value instead of '" + s + "'")
    return str(s)

ZIP_PASSWORD = b'infected'
headers = {'API-KEY': ''}

# Hardcoded input file name
input_file = 'samples.json'

try:
    with open(input_file) as json_file:
        data = json.load(json_file)
except FileNotFoundError:
    print("Mal-Parse ran into an unknown error. Please try again.")
    sys.exit(1) 

num_samples = len(data)
with tqdm(total=num_samples, desc="Downloading", unit="sample") as pbar:
    for index, sample in enumerate(data, start=1):
        sha256_hash = sample.get('sha256_hash')
        if sha256_hash:
            response = requests.post('https://mb-api.abuse.ch/api/v1/', data={'query': 'get_file', 'sha256_hash': sha256_hash}, timeout=15, headers=headers, allow_redirects=True)

            if 'file_not_found' in response.text:
                print(f"Error: File not found for hash {sha256_hash}")
                continue

            with open(f"samples/{sha256_hash}.zip", 'wb') as file:
                file.write(response.content)

            try:
                with pyzipper.AESZipFile(f"samples/{sha256_hash}.zip") as zf:
                    zf.pwd = ZIP_PASSWORD
                    zf.extractall("samples")

                pbar.set_postfix({"Progress": f"{index}/{num_samples}"})
                pbar.update(1)

                print(f"Sample \"{sha256_hash}\" downloaded and unpacked.")

            except pyzipper.BadZipFile:
                print(f"Error: File for hash {sha256_hash} is not a zip file. Skipping.")

print("Download completed. Please wait.")


# -----------------------------------------------------> END PYTHON3 COMMAND <-------------------------------------------------------------

time.sleep(30)
os.chdir('samples/')
print(f"{green}Removing unwanted file types...{white}")
execute_command('rm *.zip')

time.sleep(5)
os.chdir('..')

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-------------------------------------------------------------

os.system('clear')

# Stage 2: Malware Sample Collection
print(f"{green}Stage 2/9: Collecting Malware Samples{white}")

def yarGen_execution(first_time=False):

    print(f"{gold}Checking to see if unzip is installed..{white}.")

    unzip_installed = execute_quiet_command(['which', 'unzip'])

    if not unzip_installed:
        execute_quiet_command(['sudo', 'apt-get', 'install', 'unzip', 'y'])

    print(f"{green}Unzipping... Please wait...{white}")

    if os.path.exists('0.23.4.zip'):
        print(f"{white}Unzipping... Please wait...{white}")
        execute_quiet_command(['unzip', '-e', '0.23.4.zip'])

    if os.path.exists('0.23.4.zip'):
        os.remove("0.23.4.zip")

    if not os.path.exists('yarGen'):
        shutil.move('yarGen-0.23.4', 'yarGen')
    else:
        print(f"Directory 'yarGen' already exists. Skipping move operation.")

    os.chdir('yarGen')

    print(f"{gold}Double checking to see if pip is installed...{green}")

    pip_installed = execute_quiet_command(['which', 'pip'])

    if not os.path.exists('yargen_rules.yar'):
        with open('yargen_rules.yar', 'w') as f:
            pass

    if not pip_installed:
        execute_quiet_command(['sudo', 'apt-get', 'install', 'python3-pip', 'y'])
        
    print(f"{gold}Installing yarGen requirements...{green}")
    execute_quiet_command(['pip', 'install', '-r','requirements.txt'])
    
    if first_time:
        print(f"{white}Updaing DB to most recent version. This may take up to 2 minutes. Please wait...{white}")
        execute_quiet_command(['python3', 'yarGen.py', '--update'])
        time.sleep(5)
    
    print(f"{white}Finally executing rule generator. Please wait up to 5 minutes. {white}")
    
    spinner = Halo(text='Loading...', spinner='dots')
    
    spinner.start()
    execute_quiet_command(['python3', 'yarGen.py', '-a', 'Grim', '-r', '@grimbinary', '-m', '../../malware/samples'])
    spinner.stop()
    print(f"{green}YARA rule generator has been successfully executed.{white}")

if not os.path.exists('yarGen'):
    print(f"{white}Downloading rule generator...")
    execute_quiet_command(['wget', 'https://github.com/Neo23x0/yarGen/archive/refs/tags/0.23.4.zip'])


if db_update.lower() == 'y' or not os.path.exists('yarGen'):
    if not os.path.exists('yarGen'):
        print(f"{gold}The yarGen script will not run without being updated at least once. Updating now...{white}")
    yarGen_execution(first_time=True)
else:
    print(f"{white}Skipping DB update.{white}")
    yarGen_execution(first_time=False)

shutil.move('yargen_rules.yar', 'rules.yar')

execute_command("cp rules.yar ../")

# -----------------------------------------------------> END PYTHON3 COMMAND <-------------------------------------------------------------

time.sleep(5)

print(f"{gold}Sending to YARAify Rule Sharing Platform. Please Standby... {white}")


# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

# Stage 3: YARA Rule Generation and Transmission
print(f"{green}Stage 3/9 (optional): Generating and Transmitting YARA Rules to YARAify{white}")

def yaraify_transmission():
    yaraify_api_url = config.get('YARAify', 'yaraify_api_url', fallback='https://yaraify-api.abuse.ch/api/v1/')

    create_directory('yaraify')

    for file in os.listdir('yaraify'):
        if file.endswith('.yar'):
            os.remove(f'yaraify/{file}')

    with open('rules.yar', 'r') as f:
        data = f.read()

    rules = re.findall(r'rule\s+.*?{.*?}', data, re.DOTALL)

    for i, rule in enumerate(rules):
        matches = re.findall(r'hash\d*\s*=\s*"([a-fA-F0-9]+)"', rule, re.IGNORECASE)
        for j, sha256_hash in enumerate(matches):
            try:
                with open(f'samples/{sha256_hash}.exe', 'rb') as f:
                    md5_hash = hashlib.md5(f.read()).hexdigest()

                rule_uuid = str(uuid.uuid4())

                rule = re.sub(r'{', r'\n{', rule, count=1)

                rule = re.sub(r'(date\s*=\s*"[^"]+")', fr'\1\n      yarahub_license = "CC0 1.0"\n      yarahub_rule_matching_tlp = "TLP:WHITE"\n      yarahub_rule_sharing_tlp = "TLP:GREEN"\n      yarahub_uuid = "{rule_uuid}"\n      yarahub_reference_md5 = "{md5_hash}"', rule)

                with open(f'rule_{sha256_hash}.yar', 'w') as f:
                    f.write(rule)

                if os.path.exists(f'yaraify/rule_{sha256_hash}.yar'):
                    os.remove(f'yaraify/rule_{sha256_hash}.yar')

                shutil.move(f'rule_{sha256_hash}.yar', 'yaraify/')
                
                with open(f'yaraify/rule_{sha256_hash}.yar', 'rb') as f:
                    response = requests.post(yaraify_api_url, files={'file': f})

                if response.status_code == 200:
                    print(f'Successfully submitted rule_{sha256_hash}.yar to yaraify')
                else:
                    print(f'Error submitting rule_{sha256_hash}.yar to yaraify: {response.text}')

                print(f'Upload progress: {i + 1}/{len(rules)}')
            except FileNotFoundError:
                print(f"File {sha256_hash}.exe moving to next hash.")
                continue

    print(f"{green}Transmission complete.{white}")

if yaraify_transmission_choice.lower() == 'y':
    yaraify_transmission()
else:
    print(f"{gold}Skipping YARAify transmission...{white}")

# -----------------------------------------------------> END PYTHON3 COMMAND <-----------------------------------------------------

time.sleep(3)
time.sleep(5)
print(f"{gold}Please Wait...{white}")
os.chdir(os.path.expanduser('~/mal-parse/malware'))
execute_command('cp hashes.json ~/mal-parse/investigate')
os.chdir(os.path.expanduser('~/mal-parse/investigate'))
time.sleep(3)

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

os.system('clear')

# Stage 4: Malware Sample Information Query
print(f"{green}Stage 4/9: Querying Malware Sample Information{white}")


API_URL="https://mb-api.abuse.ch/api/v1/"
REPORT_FILE="report.json"

def query_sample_info(hash):
    print(f"Querying sample info for hash: {hash}")
    response = requests.post(API_URL, data={"query": "get_info", "hash": hash})
    try:
        response_data = response.json().get('data', {})
    except json.JSONDecodeError:
        print(f"Warning: Received invalid JSON response for hash: {hash}")
        return {}
    if not response_data:
        return {}
    else:
        return response_data

try:
    with open("hashes.json", 'r') as f:
        hashes = json.load(f)['data']
except json.JSONDecodeError:
    print("Error: hashes.json is not valid JSON.")
    exit(1)

total_hashes = len(hashes)
current_hash = 1

print("Starting sample info extraction...")
print(f"Total hashes: {total_hashes}")

report = {"query_status": "ok", "data": []}

for hash_info in hashes:
    hash = hash_info['sha256_hash']
    print(f"Progress: {current_hash} / {total_hashes}")
    report_data = query_sample_info(hash)
    if isinstance(report_data, list):
        report['data'].extend(report_data)
    else:
        report['data'].append(report_data)
    current_hash += 1

print("Sample info extraction completed.")

try:
    with open("report.json", 'w') as f:
        json.dump(report, f, indent=4)
except Exception as e:
    print(f"Error writing to report file: {e}")
    exit(1)

time.sleep(5)

try:
    with open('report.json', 'r') as file:
        report_content = file.read()
except Exception as e:
    print(f"Error reading report file: {e}")
    exit(1)

# Replace "][" with ","
formatted_report = report_content.replace("        ],\n        [", ",").replace(": [[",": [" ).replace("    'data': \n [", " 'data' :\n").replace("            } \n       ]       ]\n}", "  }\n]\n}")

subprocess.run("sed -i 's/]\[/,/g' report.json", shell=True)
subprocess.run("sed -i '$s/]/]}/' report.json", shell=True)
subprocess.run(r'''sed -i 's/{\n    "query_status": "ok",\n    "data": \n        \[/\n{\n    "query_status": "ok",\n    "data": /g' report.json''', shell=True)

try:
    with open('formatted_report.json', 'w') as file:
        file.write(formatted_report)
except Exception as e:
    print(f"Error writing to formatted_report.json: {e}")
    exit(1)

print("JSON formatting completed.")


# -----------------------------------------------------> END PYTHON3 COMMAND <-----------------------------------------------------

time.sleep(5)
print(f"{gold}Now beginning integration with ELK stack...{white}")
time.sleep(5)

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

# Stage 5: Sending Data to ElasticSearch
print(f"{green}Stage 5/9 (optional): Sending Data to ElasticSearch{white}")
 
def send_to_kibana(ip_address, port, file_name):
    print("Please wait...")
    time.sleep(5)
    os.chdir(os.path.expanduser('~/mal-parse/investigate'))
    
    time.sleep(5)
    print("Transferring now...")
    scheme = 'http'
    host = ip_address
    port = port
    index_name = file_name
    es = Elasticsearch([f'{scheme}://{host}:{port}'], request_timeout=60, max_retries=10, retry_on_timeout=True)

    mapping = {
        "properties": {
            "intelligence": {
                "properties": {
                    "clamav": {
                        "type": "keyword"
                    },
                    "downloads": {
                        "type": "integer"
                    },
                    "uploads": {
                        "type": "integer"
                    },
                    "mail": {
                        "type": "keyword"
                    }
                }
            }
        }
    }


    es.indices.create(index=index_name, body={"mappings": mapping})

    # Directory containing the hashes.json file
    json_dir = './'
    json_file = 'formatted_report.json'
    json_path = os.path.join(json_dir, json_file)

    if not os.path.exists(json_path):
        print(f"The JSON file '{json_file}' does not exist.")
        exit(1)

    with open(json_path, 'r') as file:
        json_content = file.read()

    json_data = json.loads(json_content)

    for sample in json_data['data']:
        sha256_hash = sample.get('sha256_hash', '')
        md5_hash = sample.get('md5_hash', '')
        first_seen = sample.get('first_seen', '')
        last_seen = sample.get('last_seen', '')
        file_name = sample.get('file_name', '')
        file_size = sample.get('file_size', '')
        file_type_mime = sample.get('file_type_mime', '')
        file_type = sample.get('file_type', '')
        reporter = sample.get('reporter', '')
        origin_country = sample.get('origin_country', '')
        signature = sample.get('signature', '')
        tags = sample.get('tags', '')
        comment = sample.get('comment', '')
        delivery_method = sample.get('delivery_method', '')
        intelligence = sample.get('intelligence', {})

        # Preparing the following data to be sent to Elasticsearch
        document = {
            'sha256_hash': sha256_hash,
            'md5_hash': md5_hash,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'file_name': file_name,
            'file_size': file_size,
            'file_type_mime': file_type_mime,
            'file_type': file_type,
            'reporter': reporter,
            'origin_country': origin_country,
            'signature': signature,
            'tags': tags,
            'comment': comment,
            'delivery_method': delivery_method,
            'intelligence': intelligence
        }

        # Index the data in Elasticsearch
        response = es.index(index=index_name, body=document)

        # Check the response from Elasticsearch
        if response['result'] == 'created':
            print(f"Data for sample '{sha256_hash}' indexed successfully.")
        else:
            print(f"Failed to index data for sample '{sha256_hash}'.")
    print(f"{green}ElasticSearch transmission complete.{white}")


if kibana_transmission_choice.lower() == 'y':
    if interactive_mode:
        ip_address = input("Please enter the IP address of your ElasticSearch instance: ")
        port = input("Please enter the port (default is 9200): ") or "9200"
        kibana_file_name = input("Please enter the name of the file (default is 'threat_analysis_grimbinary_todaysdate'): ") or f'threat_analysis_grimbinary_{datetime.now().strftime("%Y-%m-%d")}'
    else:
        ip_address = config.get('Kibana', 'kibana_ip_address', fallback='127.0.0.1')
        port = config.get('Kibana', 'kibana_port', fallback='9200')
        kibana_file_name = config.get('Kibana', 'kibana_file_name', fallback=None)
        if kibana_file_name == 'threat_analysis_grimbinary_todaysdate':
            kibana_file_name = f'threat_analysis_grimbinary_{datetime.now().strftime("%Y-%m-%d")}'

    send_to_kibana(ip_address, port, kibana_file_name)
else:
    print(f"Skipping ElasticSearch transmission...")

# -----------------------------------------------------> END PYTHON3 COMMAND <-----------------------------------------------------

time.sleep(10)
os.system('clear')

# Stage 6: ThreatFox Transmission
print(f"{green}Stage 6/9: Transmitting Data to ThreatFox{white}")

def send_to_threatfox(api_key):
    print(f"{gold}Sending files to ThreatFox...{white}")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    headers = {
      "API-KEY": api_key,
    }

    pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=100, headers=headers, cert_reqs='CERT_NONE', assert_hostname=True)

    with open('formatted_report.json', 'r') as f:
        data = json.load(f)
   
    for item in tqdm(data['data'], desc='Uploading samples to ThreatFox'):
        sha256_hash = item['sha256_hash']
        threat_type = "payload"
        ioc_type = 'sha256_hash'
        confidence_level = 75
        tags = item.get('tags', [])
        malware = ['win.' + tag.lower().replace(' ', '') for tag in tags if tag != 'exe']
        iocs = [sha256_hash]

        filtered_item = {
            'query': 'submit_ioc',
            'threat_type': threat_type,
            'ioc_type': ioc_type,
            'malware': malware[:1],
            'confidence_level': confidence_level,
            'tags': tags[:2],
            'iocs': iocs
        }

        json_data = json.dumps(filtered_item)
        response = pool.request("POST", "/api/v1/", body=json_data)

        if response.status == 200 or response.status == 201:
            print(f'Successfully submitted sample {sha256_hash} to ThreatFox')
        else:
            print(f'Error submitting sample {sha256_hash} to ThreatFox: {response.status} {response.reason}')

    print(f"{green}Completed ThreatFox transmission.{white}")


if threatfox_transmission_choice.lower() == 'y':
    if interactive_mode:
        api_key = input("Please enter your API key: ")
    else:
        api_key = config.get('ThreatFox', 'threatfox_api_key', fallback=None)

    send_to_threatfox(api_key)
else:
    print(f"{gold}Skipping ThreatFox transmission...{white}")

# -----------------------------------------------------> END PYTHON3 COMMANDS <-----------------------------------------------------

print(f"{gold}Condensing files so that they can be analyzed with AI... Please wait...{white}")
time.sleep(5)

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

folder_name = "sample_hashes"
os.makedirs(folder_name, exist_ok=True)

try:
    with open('formatted_report.json', 'r') as f:
        report_content = f.read()
except Exception as e:
    print(f"Error reading report file: {e}")
    exit(1)

try:
    report_data = json.loads(report_content)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON data: {e}")
    exit(1)

samples = report_data.get('data', [])


for sample in samples:
    try:
        sha256_hash = sample['sha256_hash']

        file_name = f"{sha256_hash}.json"
        file_path = os.path.join(folder_name, file_name)
        with open(file_path, 'w') as f:

            json.dump(sample, f, indent=4)

        print(f"Sample {sha256_hash} saved to file: {file_path}")
    except Exception as e:
        print(f"Error while processing sample {sample}. Error: {e}")
        continue

print(f"Files have been condensed. Shortening files....")


def truncate_text(text, length):
    if len(text) <= length:
        return text
    else:
        return text[:length] + '...'

def convert_json_to_text(file_path):
    with open(file_path, 'r') as f:
        json_data = json.load(f)
    return json.dumps(json_data)


def reduce_text_length(text, limit):
    return truncate_text(text, limit)

directory = 'sample_hashes'

output_directory = 'reduced_sample_files'

os.makedirs(output_directory, exist_ok=True)


for filename in os.listdir(directory):
    if filename.endswith('.json'):
        file_path = os.path.join(directory, filename)
        output_file_path = os.path.join(output_directory, filename[:-5] + '_reduced.txt')
       
        text = convert_json_to_text(file_path)
       
        reduced_text = reduce_text_length(text, 1600)
       
        with open(output_file_path, 'w') as f:
            f.write(reduced_text)
       
        print(f"Sample {filename} reduced and saved to file: {output_file_path}")
print(f"Files have been shortened.")

# -----------------------------------------------------> END PYTHON3 COMMANDS <-----------------------------------------------------
time.sleep(5)
print(f"{gold}Analyzing...{white}")
os.chdir(os.path.expanduser('~/mal-parse/investigate/'))

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------


os.system('clear')

# Stage 7: AI Analysis with OpenAI
print(f"{green}Stage 7/9 (optional): Summarizing Malware Samples with AI Analysis{white}")

def ai_analysis_execution(openai_api_key, engine_choice, prompt):

    openai.api_key = openai_api_key

    directory2 = 'reduced_sample_files'

    output_directory2 = 'ai_report'

    os.makedirs(output_directory2, exist_ok=True)


    total_files = len([filename for filename in os.listdir(directory2) if filename.endswith('.txt')])


    progress_bar = tqdm(total=total_files, unit='file(s)')


    for filename in os.listdir(directory2):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory2, filename)
            output_file_path2 = os.path.join(output_directory2, filename[:-4] + '_ai_report.txt')

            with open(file_path, 'r') as f:
                sample_content = f.read()

            try:
                response = openai.Completion.create(
                    engine=engine_choice,
                    prompt = prompt + sample_content,
                    temperature=0.7,
                    max_tokens=800,
                    n=1,
                    stop=None
                )
                summary = response.choices[0].text.strip()

            except Exception as e:
                print(f"An error occurred while generating the summary: {e}")
                summary = "Error generating summary."
        
            with open(output_file_path2, 'w') as f:
                f.write(summary)

            progress_bar.set_description(f"Analyzing: {filename}. This will take time.")
            progress_bar.update(1)


    progress_bar.close()
    print("Done.")
    time.sleep(5)
    os.system('clear')
# -----------------------------------------------------> END PYTHON3 COMMANDS <-----------------------------------------------------

time.sleep(5)
print(f"{gold}Please Wait...{white}")
os.chdir(os.path.expanduser('~/mal-parse/investigate'))

# -----------------------------------------------------> ENTER PYTHON3 COMMANDS HERE <-----------------------------------------------------

# Stage 8: Report Transmission
print(f"{green}Stage 8/9 (optional): Sending Threat Analysis Report{white}")

def send_to_platform():
    if platform_choice == 'y':
        if platform.lower() == 'discord':
            from discord_webhook import DiscordWebhook
            discord_webhook = DiscordWebhook(url=discord_webhook_url)

            with open('report.txt', 'rb') as f:
                discord_webhook.add_file(file=f.read(), filename='report.txt')

            response = discord_webhook.execute()

        elif platform.lower() == 'slack':
            from slack_sdk import WebClient
            from slack_sdk.errors import SlackApiError
            client = WebClient(token=slack_token)
            print("Sending...")

            try:
                response = client.files_upload(
                    channels=slack_channel_id,
                    initial_comment="Daily threat analysis brief",
                    file='report.txt'
                )
            except SlackApiError as e:
                print(f"Error sending file: {e}")

        print(f"{green}Threat report has been sent to your chosen service.{white}")

# Stage 9: Threat Analysis Completion
print(f"{green}Stage 9/9: Beginning Open-source Threat Analysis{white}")

hashes_file_path = 'hashes.json'
output_directory = 'threat_analysis/'
vt_api_endpoint = 'https://www.virustotal.com/api/v3/files/{}/behaviour_mitre_trees'

vt_api_key = config.get('Virustotal', 'vt_api_key', fallback=None)
if vt_api_key is None:
    vt_api_key = input("Please enter your VirusTotal API key: ")

os.makedirs(output_directory, exist_ok=True)

with open(hashes_file_path, 'r') as f:
    hashes_data = json.load(f)

for sample in hashes_data['data']:
    sha256_hash = sample['sha256_hash']
    signature = sample['signature']
    output_file = os.path.join(output_directory, f'{sha256_hash}_threat.txt')

    print(f"Performing threat analysis for sample: {sha256_hash}")

    url = vt_api_endpoint.format(sha256_hash)
    headers = {'x-apikey': vt_api_key }

    response = requests.get(url, headers=headers)

    with open(output_file, 'w') as f:
        f.write(f"Sample: {signature} : {sha256_hash}\n\n")
        f.write(response.text)

    print(f"Threat analysis result saved to: {output_file}")

print(f"{green}Threat analysis completed.{white}")

print(f"{white}Please Wait...{white}")

os.chdir(os.path.expanduser('~/mal-parse/investigate/threat_analysis/'))
os.system("touch report.txt")

with open('report.txt', 'w') as outfile:
    for filename in os.listdir():
        if filename.endswith('.txt'):
            with open(filename) as infile:
                outfile.write(infile.read())


send_to_platform()


# -----------------------------------------------------> END PYTHON3 COMMANDS <-----------------------------------------------------


# -----------------------------------------------------> START PYTHON3 COMMANDS HERE <-----------------------------------------------------
time.sleep(5)
os.system('clear')

os.chdir(os.path.expanduser('~/mal-parse/investigate/threat_analysis/'))
if os.path.exists("report.txt"):
    os.rename("report.txt", "new_threats.json")

os.chdir(os.path.expanduser('~/mal-parse/'))

print(f"{green}Done.{green}")
print(f"{green}All stages met. Thank you for using Mal-Parse!{green}")
print(f"{green}To start the dashboard, please navigate to the /admin/ directory and execute 'start-dashboard.py'{green}")

# -----------------------------------------------------> END PYTHON3 COMMANDS <-----------------------------------------------------
