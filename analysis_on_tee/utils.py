import re

import requests
import os
import random
import pathlib
import sys
import pandas as pd

def get_files_from_directory(dir_path):

    files = os.listdir(dir_path)
    files = [f for f in files if os.path.isfile(dir_path+'/'+f)]

    return files

def get_file_details(arg, file):
    file_path = arg+file
    filename = file_path.split('/')[-1]
    realfile = filename.split('.')[0]
    file_extension = filename.split('.')[-1]
    
    return file_path, filename, realfile, file_extension
    
def extract_ips(text):
    # Define a regular expression pattern for matching IPv4 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Find all matches in the text using the regex pattern
    matches = re.findall(ipv4_pattern, text)

    # Remove duplicates by converting the list to a set and back to a list
    unique_ips = list(set(matches))

    return unique_ips

def search_ip_in_bloclists(ip, blocklists=[
'https://cdn.ellio.tech/community-feed',
'https://lists.blocklist.de/lists/all.txt',
'https://dataplane.org/proto41.txt', #
'https://malsilo.gitlab.io/feeds/dumps/ip_list.txt',
'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
'https://snort.org/downloads/ip-block-list',
'https://home.nuug.no/~peter/pop3gropers.txt',
'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset',
# 'https://cinsscore.com/list/ci-badguys.txt',  # this blocklist returns an error ('Connection broken: IncompleteRead')
'https://dataplane.org/vncrfb.txt' #
]):
    found_in = []
    for blocklist in blocklists:
        resp = requests.get(blocklist)
        extracted_ips= extract_ips(resp.text)

        if ip in extracted_ips:
            found_in.append(blocklist)

    return found_in

def search_domain_in_bloclists(domain, blocklists=[
'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt',
'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_optional.txt',
'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_browser.txt',
'https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt',
'https://openphish.com/feed.txt',
]):
    found_in = []
    for blocklist in blocklists:
        resp = requests.get(blocklist)
        # extracted_domains= resp.text.split('\n')
        extracted_domains = extract_domains(resp.text)
        # print(f"Extracted domains of {blocklist}: ", extracted_domains)

        if domain in extracted_domains:
            found_in.append(blocklist)

    return found_in

def extract_domains(text):
    # Define a regular expression pattern for matching domain names without "http://" or "https://"
    domain_pattern = r'\b(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+)\b'

    # Find all matches in the text using the regex pattern
    matches = re.findall(domain_pattern, text)

    # Remove duplicates by converting the list to a set and back to a list
    unique_domains = list(set(matches))

    return unique_domains

def search_email_in_blocklist(arg, blocklists=[
'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt',
'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_optional.txt',
'https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list_browser.txt',
'https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt',
'https://openphish.com/feed.txt'
]):
    found_in = []
    for blocklist in blocklists:
        resp = requests.get(blocklist)
        extracted_emails = extract_emails(resp.text)

        if arg in extracted_emails:
            found_in.append(blocklist)

    return found_in


def extract_emails(text):
    # Define a regular expression pattern for matching emails"
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    # Find all matches in the text using the regex pattern
    matches = re.findall(email_pattern, text)

    # Remove duplicates by converting the list to a set and back to a list
    unique_emails = list(set(matches))

    return unique_emails

def clear_dataset(file_path, filename):
    # Run only the first time in order to clean the specific file we used
    # Random sample of ENCRYPT_8BELLS_logs_09012024.txt
    file_name_only = filename.split('.')[0]
    short_file = file_name_only + '_short'

    with open(file_path) as file:
        lines = random.sample(file.readlines(), 500)

    new_file_path = "./Datasets/" + short_file + '.txt'
    with open(new_file_path, 'w') as fout:
        fout.writelines(lines)

    # Delete old file from directory
    pathlib.Path.unlink(file_path)

    file_path = new_file_path
    clear_file = "./Datasets/" + short_file + '_clear.txt'
    delete_list = [",PSH", ",FIN", ",RST", ",SYN", "SYN,", ", code 3", ", code 0", ", code 1"]
    with open(file_path) as file, open(clear_file, '+w') as fout:
        for line in file:
            for word in delete_list:
                line = line.replace(word, "")
            fout.write(line)

    # Delete old file from directory
    pathlib.Path.unlink(file_path)

    return clear_file

def check_empty_file_and_delete(file):
    if os.path.getsize(file) == 0:
        pathlib.Path.unlink(file)
        

def fill_file(ip, ip_dest, ip_port, file):
    
    temp_ip = extract_ips(ip)
    ip_address = ' '.join(temp_ip)

    with open(file, '+a') as f:
        sys.stdout = f

        print(f"ip_address: {ip_address}")
        print("  destinations_ip: ", ip_dest)
        print("  ip_ports: ", ip_port)
        print("")

def increase_by_1(value):
    value +=1 
    return value


def get_filename(file_path):
    filename = file_path.split('/')[-1]
    realfile = filename.split('.')[0]
    return realfile

def delete_files(files):
    for file in files:
        pathlib.Path.unlink(file)

def correlation(list1, list2):
    for ip2 in list2:
        for ip1 in list1:
            if ip2 == ip1:
                return True
            
def merge_files(output_file, output_file_block):
    with open(output_file, '+a') as outfile:
        with open(output_file_block) as infile:
            for line in infile:
                outfile.write(line)
