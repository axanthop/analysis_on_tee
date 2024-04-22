import pandas as pd
import re
import os
import sys
import shutil
import pathlib

from utils import clear_dataset, check_empty_file_and_delete, fill_file, merge_files, delete_files
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
        with open(output_file, 'a') as f:
            sys.stdout = f
            print(f"\nAnalyzing IP entry: {ip_address}")
            flag_ip = extract_ips(ip_address)
            converted_flag = ' '.join(flag_ip)
            # Filter the DataFrame for entries related to the specified IP address
            ip_specific_data = data[data['sourceIP'] == ip_address]
            ip_specific_data_reset = ip_specific_data.reset_index(drop=True)

            if ip_specific_data.empty:
                print(f"No data found for IP address: {ip_address}")
                return
            
            ip_dest = []
            ip_port = []

            # Iterate and print details for each entry
            for index, row in ip_specific_data_reset.iterrows():
                print(f"Entry {index + 1}:")
                print(f"  Time: {row['time']}")
                print(f"  Source IP: {row['sourceIP']}")
                print(f"  Source Port: {row['sourcePort']}")
                print(f"  Destination IP: {row['destinationIP']}")
                if row['destinationIP'] not in ip_dest:
                    ip_dest.append(row['destinationIP'])
                print(f"  Destination Port: {row['destinationPort']}")
                if row['destinationPort'] not in ip_port:
                    ip_port.append(row['destinationPort'])
                print(f"  Destination NAT IP: {row['natDestinationIP']}")
                print(f"  Destination NAT Port: {row['natDestinationPort']}")
            sys.stdout.flush()
        f.close()
        return ip_dest, ip_port
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while analyzing IP address {ip_address}: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__

def extract_private_ip_addresses(dataset_file, private_ips):
    unique_ips = set()

    with open(dataset_file, 'r') as f:
        for line in f:
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+:\d+)'
            ip_matches = re.findall(ip_pattern, r'' + str(line))
            ip_list = list(ip_matches)
            unique_ips.add(ip_list[1].split(':')[0])


    # Write the unique IPs to the private_ips file
    with open(private_ips, 'w') as f:
        f.write("Private IP found")
        f.write("\n")
        for i, ip in enumerate(unique_ips):
            f.write(ip)
            if i != len(unique_ips) - 1:  # Check if it's not the last IP address
                f.write('\n')

def analyze_suspicious_bot_attacks(data, outputfilebotnet, private_ips_file, private_bells_correlation_file):
    try:
        with open(private_ips_file, 'r') as f:
            private_ips = [line.strip() for line in f]

        with open(outputfilebotnet, 'a+') as f:
            sys.stdout = f
            print("")
            print("========== Potentially Bot-related Attacks ===========")

            # Filter the DataFrame for entries with source IP addresses in private_ips
            suspicious_ips_data = data[data['sourceIP'].isin(private_ips)]
            suspicious_ips_data_reset = suspicious_ips_data.reset_index(drop=True)

            if suspicious_ips_data_reset.empty:
                # print("")
                return

            # Display IP Entry Access Frequency
            print("\nSuspicious private IP Addresses Related to Bot Attack - number of their attacks")
            print(suspicious_ips_data_reset['sourceIP'].value_counts())
            sys.stdout.flush()
        f.close()
        with open(outputfilebotnet, 'a+') as f:
            sys.stdout = f
            # Analyze all suspicious IP address entries
            for ip_address in suspicious_ips_data_reset['sourceIP'].unique():
                ip_dest, ip_port = analyze_ip_address(data, ip_address, outputfilebotnet)

                fill_file(ip_address, ip_dest, ip_port, private_bells_correlation_file)

        f.close()
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while analyzing suspicious IPs: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__

def data_process(file_path, filename, output_file, private_info, outputfilebotnet, 
                 bells_correlation_file, private_bells_correlation_file, reports_directory):
    try:

        # ===========================================================================
        # Run only the first time for the given dataset to take a small random sample
        # and clean the data in order to run the script
        # Comment the following command if you run the script again
        # 
        file_path = clear_dataset(file_path, filename)
        # ===========================================================================

        extract_private_ip_addresses(file_path, private_info)

        # Read CSV file and preprocess the data
        df = pd.read_csv(file_path, header=None)

        # Regex pattern for IP addresses,  port numbers and time
        pattern = r'(\d+\.\d+\.\d+\.\d+:\d+)'
        # time_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)'
        time_pattern = r'([A-Za-z0-9]+(/[A-Za-z0-9]+)+)\s([A-Za-z0-9]+(:[A-Za-z0-9]+)+)'


        # Function to extract values using the regex pattern
        def extract_values(row):
            string_list = [str(x) for x in row]
            result_string = ','.join(string_list)
            time_matches = re.findall(time_pattern, r''+str(result_string))
            time_list = list(time_matches)
            matches = re.findall(pattern, r''+str(result_string))
            match_list = list(matches)

            if len(match_list) >= 2:
                return pd.Series({
                    'time': time_list[0],
                    'sourceIP': match_list[0].split(':')[0],
                    'sourcePort': match_list[0].split(':')[1],
                    'destinationIP': match_list[1].split(':')[0],
                    'destinationPort': match_list[1].split(':')[1],
                    'natDestinationIP': match_list[-1].split(':')[0],
                    'natDestinationPort': match_list[-1].split(':')[1]
                })
            else:
                return pd.Series({
                    'time': None,
                    'sourceIP': None,
                    'sourcePort': None,
                    'destinationIP': None,
                    'destinationPort': None,
                    'natDestinationIP': None,
                    'natDestinationPort': None
                })


        # Extract source IP, source port, destination IP, destination port, nat destination IP, and nat destination port
        df[['time', 'sourceIP', 'sourcePort', 'destinationIP', 'destinationPort', 'natDestinationIP', 
            'natDestinationPort']] = df.apply(lambda row: extract_values(row), axis=1
        )


        # Anomaly Detection - Detecting unusual IP addresses
        source_ip_col = 'sourceIP'
        suspicious_ips = df[source_ip_col].value_counts()

        with open(output_file, 'w') as f:
            sys.stdout = f

            # Display IP Address Access Frequency
            print("\nIP Address Access Frequency:")
            print(suspicious_ips)

            # Check for any IP addresses with unusually high access frequency
            threshold = 1  # Adjust threshold as needed
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
                sys.stdout.flush()
            f.close()


            # Analyze all suspicious IP address entries
            for ip_address in suspicious_ips[suspicious_ips > threshold].index:

                ip_dest, ip_port = analyze_ip_address(df, ip_address, output_file)

                fill_file(ip_address, ip_dest, ip_port, bells_correlation_file)

            # Analyze the most suspicious IP address
            # analyze_ip_address(df, most_suspicious_ip)
                
                
            with open(outputfilebotnet, 'w') as f:
                sys.stdout = f
                analyze_suspicious_bot_attacks(df, outputfilebotnet, private_info,
                                                private_bells_correlation_file)

            # Check if the outputfilebotnet is empty and if so, delete it
            check_empty_file_and_delete(outputfilebotnet)
            
            if not os.path.exists(reports_directory):
                os.mkdir(reports_directory)
            shutil.move(output_file, reports_directory)
            shutil.move(outputfilebotnet, reports_directory)

    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while processing the data: {e}")
    finally:
        # Restore sys.stdout to its original value to avoid interference in the Jupyter Notebook or interactive environments
        sys.stdout = sys.__stdout__