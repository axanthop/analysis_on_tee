import pandas as pd
import json
import os
import sys
import pathlib
import shutil

from utils import check_empty_file_and_delete, fill_file, merge_files, delete_files
from utils import extract_ips, search_ip_in_bloclists

pd.set_option('display.max_rows', None)

def analyze_ip_address(data, ip_address, output_file):
    """
    Analyze entries in a DataFrame related to a specific IP address.

    :param data: DataFrame containing the network security group event data.
    :param ip_address: The IP address to filter and analyze.
    :param output_file: The file of the analysis report for IPs.
    :param found_ips: A list of IPs found in blocklists.
    """
    try:
        with open(output_file, 'a+') as f:
            sys.stdout = f
            print(f"\nAnalyzing IP entry: {ip_address}")
            flag_ip = extract_ips(ip_address)
            converted_flag = ' '.join(flag_ip)
            # Filter the DataFrame for entries related to the specified IP address
            ip_specific_data = data[data['properties.conditions.sourceIP'] == ip_address]

            if ip_specific_data.empty:
                print(f"No data found for IP address: {ip_address}")
                return
            
            ip_dest = []
            ip_port = []
            
            # Iterate and print details for each entry
            for index, row in ip_specific_data.iterrows():
                print(f"Entry {index + 1}:")
                print(f"  Time: {row['time']}")
                if 'properties.ruleName' in row.index:
                    print(f"  Rule Name: {row['properties.ruleName']}")
                else:
                    print("  Rule Name: None")
                print(f"  Direction: {row['properties.direction']}")
                if 'properties.priority' in row.index:
                    print(f"  Priority: {row['properties.priority']}")
                else:
                    print(f"  Priority: None")
                print(f"  Type: {row['properties.type']}")
                print(f"  Source Port Range: {row['properties.conditions.sourcePortRange']}")
                print(f"  Destination Port Range: {row['properties.conditions.destinationPortRange']}")
                if row['properties.conditions.destinationPortRange'] not in ip_port:
                    ip_port.append(row['properties.conditions.destinationPortRange'])
                print(f"  Source IP: {row['properties.conditions.sourceIP']}")
                print(f"  Destination IP: {row['properties.conditions.destinationIP']}")
                if row['properties.conditions.destinationIP'] not in ip_dest:
                    ip_dest.append(row['properties.conditions.destinationIP'])
                print("\n")
            ip_dest = [ip for ip in ip_dest if str(ip) != 'nan']
            converted_ip_dest = ' '.join(ip_dest)
            ip_destinations = extract_ips(converted_ip_dest)
            sys.stdout.flush()
        f.close()
        return ip_destinations, ip_port
    except Exception as e:
        print(f"An error occurred while analyzing IP address {ip_address}: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__

def extract_private_ip_addresses(dataset_file, private_ips_file):
    unique_ips = set()

    with open(dataset_file, 'r') as f:
        for line in f:
            line_data = json.loads(line)
            destination_ip = line_data.get('properties', {}).get('conditions', {}).get('destinationIP')
            if destination_ip:
                unique_ips.add(destination_ip)

    # Write the unique IPs to the private_ips file
    with open(private_ips_file, 'w') as f:
        f.write("")
        f.write("Private IPs found \n")
        ips_to_write = '\n'.join(unique_ips)
        f.write(ips_to_write)

def analyze_suspicious_bot_attacks(data, outputfilebotnet, private_ips_file, private_exus_correlation_file):
    try:
        with open(private_ips_file, 'r') as f:
            private_ips = [line.strip() for line in f]

        with open(outputfilebotnet, 'a+') as f:
            sys.stdout = f
            print("")
            print("========== Potentially Bot-related Attacks ===========")

            # Filter the DataFrame for entries with source IP addresses in private_ips
            suspicious_ips_data = data[data['properties.conditions.sourceIP'].isin(private_ips)]
            suspicious_ips_data_reset = suspicious_ips_data.reset_index(drop=True)

            if suspicious_ips_data_reset.empty:
                # print("")
                return

            # Display IP Entry Access Frequency
            print("\nSuspicious private IP Addresses Related to Bot Attack - number of their attacks")
            print(suspicious_ips_data_reset['properties.conditions.sourceIP'].value_counts())
            print("\n================== Entry Analysis ==================")
            sys.stdout.flush()

            # Analyze all suspicious IP address entries
            for ip_address in suspicious_ips_data_reset['properties.conditions.sourceIP'].unique():
                ip_dest, ip_port = analyze_ip_address(data, ip_address, outputfilebotnet)

                fill_file(ip_address, ip_dest, ip_port, private_exus_correlation_file)

    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while analyzing suspicious IPs: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__


def data_process(file_path, filename, output_file, private_info, outputfilebotnetx, 
                 exus_correlation_file, private_exus_correlation_file, reports_directory):
    try:

        extract_private_ip_addresses(file_path, private_info)

        with open(file_path, newline='') as file:
            dfs = []
            for line in file:
                line_data = json.loads(line)
                dfs.append(pd.json_normalize(line_data))

        df = pd.concat(dfs, ignore_index=True)

        # Anomaly Detection - Detecting unusual IP addresses
        source_ip_col = 'properties.conditions.sourceIP'
        suspicious_ips = df[source_ip_col].value_counts()

        with open(output_file, 'a') as f:
            sys.stdout = f

            print("\n================== Analysis Report ==================")

            # Display IP Address Access Frequency
            print("\nIP Address Access Frequency:")
            print(suspicious_ips)

            # Check for any IP addresses with unusually high access frequency
            threshold = 10  # Threshold for high frequency
            print("\nSuspicious IP Addresses (More than", threshold, "access attempts):")
            print(suspicious_ips[suspicious_ips > threshold])
            sys.stdout.flush()
        f.close()
        if suspicious_ips.empty:
            print("No IP address data found in the dataset.")
        else:
            # Identify the most suspicious IP address
            with open(output_file, 'a') as f:
                sys.stdout = f
                print("\n")
                most_suspicious_ip = suspicious_ips[suspicious_ips > threshold].idxmax()
                print(f"Most suspicious IP address: {most_suspicious_ip}")
                print("\n================== Entry Analysis ==================")
                sys.stdout.flush()
            f.close()

    
            # Analyze all suspicious IP address entries
            for ip_address in suspicious_ips[suspicious_ips > threshold].index:
                ip_dest, ip_port = analyze_ip_address(df, ip_address, output_file)

                fill_file(ip_address, ip_dest, ip_port, exus_correlation_file)


            with open(outputfilebotnetx, 'w') as f:
                sys.stdout = f
                analyze_suspicious_bot_attacks(df, outputfilebotnetx, private_info, private_exus_correlation_file)


            # Check if the outputfilebotnet is empty and if so, delete it
            check_empty_file_and_delete(outputfilebotnetx)
            
            if not os.path.exists(reports_directory):
                os.mkdir(reports_directory)
            shutil.move(output_file, reports_directory)
            shutil.move(outputfilebotnetx, reports_directory)

    except Exception as e:
        print(f"An error occurred while processing the data: {e}")
    finally:
        # Restore sys.stdout to its original value to avoid interference in the Jupyter Notebook or interactive environments
        sys.stdout = sys.__stdout__