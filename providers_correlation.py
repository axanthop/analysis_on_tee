import re
import sys
from utils import extract_ips, increase_by_1, correlation

def check_lines(file):
    with open(file, 'r') as f:
        for count, line in enumerate(f):
            pass
        return count + 1

def read_lines(file):
    with open(file) as f:
        lines = [line.rstrip('\n') for line in f]
    
    return lines

def providers_correlation_process(file_prov1, prov1_msg, file_prov2, prov2_msg, providers_correlation_file):

    try:

        # Information about exus file
        total_lines_prov1 = check_lines(file_prov1) # Starts from 0, so real total lines of file is minus 1
        lines_prov1 = read_lines(file_prov1)
        count_prov1 = 0

        # Information about bells file
        total_lines_prov2 = check_lines(file_prov2) # Starts from 0, so real total lines of file is minus 1
        lines_prov2 = read_lines(file_prov2)
        count_prov2 = 0

        with open(providers_correlation_file, '+a') as f:
            sys.stdout = f

            print(" ")
            print("================ Providers Correlation ================")
            print("This file shows the correlation between providers.")
            print(f" {prov1_msg} -> {prov2_msg}\n")

            while count_prov1 < total_lines_prov1:

                # Takes the data from the first providers file
                # for the correlation with the second file
                ip_address_prov1 = extract_ips(lines_prov1[count_prov1])
                print(f"\nThe IP address {ip_address_prov1} of {prov1_msg} file")
                count_prov1 = increase_by_1(count_prov1)
                ip_dest_prov1 = extract_ips(lines_prov1[count_prov1])
                print(" Has destination IPs: ", ip_dest_prov1)
                count_prov1 = increase_by_1(count_prov1)
                if prov1_msg == "EXUS":
                    port_pattern_prov1 = r'[0-9]+-[0-9]+'
                elif prov1_msg == "8BELLS":
                    port_pattern_prov1 = r'[0-9]+'
                ip_ports_prov1 = re.findall(port_pattern_prov1, lines_prov1[count_prov1])
                print(" And destination ports: ", ip_ports_prov1)
                count_prov1 = increase_by_1(increase_by_1(count_prov1))

                count_prov2 = 0
                corr = 0
                while count_prov2 < total_lines_prov2:

                    # Compare the data of second providers file
                    ip_address_prov2 = extract_ips(lines_prov2[count_prov2])
                    if correlation(ip_address_prov2, ip_address_prov1):
                        print(f" => This IP of {prov1_msg} FOUND in {prov2_msg} file!")
                        corr = increase_by_1(corr)
                    count_prov2 = increase_by_1(count_prov2)
                    ip_dest_prov2 = extract_ips(lines_prov2[count_prov2])
                    if correlation(ip_address_prov2, ip_address_prov1):
                        ip_dest_prov2_privacy = []
                        for ip in ip_dest_prov2:
                            privacy_ip = "XXX.XXX.XXX."+ip.split('.')[-1]
                            ip_dest_prov2_privacy.append(privacy_ip)
                        print("     reaching additional destination IPs: ", ip_dest_prov2_privacy)
                    count_prov2 = increase_by_1(count_prov2)
                    if prov2_msg == "8BELLS":
                        port_pattern_prov2 = r'[0-9]+'
                    elif prov2_msg == "EXUS":
                        port_pattern_prov2 = r'[0-9]+-[0-9]+'
                    ip_ports_prov2 = re.findall(port_pattern_prov2, lines_prov2[count_prov2])
                    if correlation(ip_address_prov2, ip_address_prov1):
                        print("     and destination ports: ", ip_ports_prov2)
                    count_prov2 = increase_by_1(increase_by_1(count_prov2))

                if corr == 0:
                    print(f" => This IP is NOT related to the {prov2_msg} file!")

            sys.stdout.flush()
        f.close()

    except Exception as e:
        print(f"An error occurred while processing the data: {e}")