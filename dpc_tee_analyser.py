import pandas as pd
import sys
import pathlib
import shutil
import os

from utils import check_empty_file_and_delete, extract_emails, extract_domains, merge_files, delete_files
from utils import search_email_in_blocklist, search_domain_in_bloclists

pd.set_option('display.max_rows', None)

def analyze_email_entry(data, email_entry, output_file, found_emails, found_domains):
    """
    Analyze entries in a DataFrame related to a specific email entry.

    :param data: DataFrame containing email event data.
    :param email_entry: The email entry to filter and analyze.
    :param output_file: The file of the analysis report for IPs.
    :param found_emails: A list of emails found in blocklists.
    :param found_emails: A list of domains found in blocklists.
    """
    try:
        # Redirect print statements to the output file
        with open(output_file, 'a+') as f:
            sys.stdout = f
            # Filter the DataFrame for entries related to the specified email entry
            email_specific_data = data[data['SenderAddress'] == email_entry]
            email_specific_data_reset = email_specific_data.reset_index(drop=True)

            if email_specific_data.empty:
                print(f"No data found for email entry: {email_entry}")
                return
            num_entries = len(email_specific_data_reset)  # Get the number of entries for this email
            print(f"\nAnalyzing email entry: {email_entry} found in {num_entries} entries.")
            flag_email = extract_emails(email_entry)
            converted_flag_email = ' '.join(flag_email)
            flag_domain = extract_domains(email_entry)
            converted_flag_domain = ' '.join(flag_domain)
            if converted_flag_email in found_emails and converted_flag_domain in found_domains:
                print("=> Flagged Email and Domain: This email and domain found being flagged in blocklists!")
            elif converted_flag_email in found_emails and converted_flag_domain not in found_domains:
                print("=> Flagged Email: This email found being flagged in blocklists!")
            elif converted_flag_domain in found_domains and converted_flag_email not in found_emails:
                print("=> Flagged Domain: This domain found being flagged in blocklists!")

            # Iterate and print details for each entry
            for index, row in email_specific_data_reset.iterrows():
                print(f"Entry {index + 1}:")
                print(f"  ReceivedTime: {row['ReceivedTime']}")
                print(f"  SenderAddress: {row['SenderAddress']}")
                print(f"  RecipientAddress: {row['RecipientAddress']}")
                print(f"  Subject: {row['Subject']}")
            sys.stdout.flush()
        f.close()
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while analyzing email entry {email_entry}: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__

def extract_unique_recipient_addresses(data, private_emails):
    try:
        # Extract unique recipient addresses
        unique_recipients = data['RecipientAddress'].unique()

        # Write the unique recipient addresses to the output file
        with open(private_emails, 'w') as f:
            for i, recipient in enumerate(unique_recipients):
                f.write(recipient)
                if i != len(unique_recipients) - 1:  # Check if it's not the last recipient address
                    f.write('\n')

    except Exception as e:
        print(f"An error occurred while extracting unique recipient addresses: {e}")

def analyze_suspicious_bot_attacks(data, outputfilebotnet, private_emails_file, found_emails, found_domains):
    try:
        # Read the private email addresses from the file
        with open(private_emails_file, 'r') as f:
            private_emails_add = [line.strip() for line in f]

        with open(outputfilebotnet, 'a+') as f:
            sys.stdout = f
            domain = "diadikasia.gr"
            suspicious_email_data = data[data['SenderAddress'].str.contains(domain)]
            suspicious_email_reset = suspicious_email_data.reset_index(drop=True) 
            domain_index = data[data['SenderAddress'].str.contains(domain)].index
            if len(domain_index) > 0:
                print("Private info:")
                for index in domain_index:
                    print(suspicious_email_data.loc[index, 'SenderAddress'])       

            if suspicious_email_reset.empty:
                # print("")
                return

            print("")
            print("========== Potentially Bot-related Attacks ===========")
            # Display Email Entry Access Frequency
            print("\nSuspicious Email Potentially Related to Bot Attack ")
            print(suspicious_email_data['SenderAddress'].value_counts())
            sys.stdout.flush()
        f.close()

        with open(outputfilebotnet, 'a+') as f:
            sys.stdout = f
            if suspicious_email_reset.empty:
                print("No suspicious email entry data found in the private email list.")
            else:
                # Analyze all suspicious email entries
                for email in suspicious_email_reset['SenderAddress'].unique():
                    analyze_email_entry(data, email, outputfilebotnet, found_emails, found_domains)
            sys.stdout.flush()
        f.close()

        # Takes the suspicious email addresses with high access frequency as input for the script
        with open(outputfilebotnet, '+a') as f:
            sys.stdout = f
            priv_emails = []
            priv_dom = []
            
            priv_emails_in = suspicious_email_reset['SenderAddress'].unique()
            for email in priv_emails_in:
                if email not in priv_emails:
                    priv_emails.append(email)
            converted_list_of_emails = ' '.join(priv_emails_in)

            # Remove empty elements
            priv_emails = [email for email in priv_emails if email != []]

            # priv_emails = list(map(' '.join, priv_emails))
            priv_dom = extract_domains(converted_list_of_emails)
            
            print("\n========== Private Information in Blocklists ===========")
            print(f"\nSearching for {len(priv_emails)} emails in blocklists...")
            for email in priv_emails:
                found_in = search_email_in_blocklist(email)
                if found_in:
                    print(f"Email [{email}] found in: ", found_in)
                else:
                    print(f"Email [{email}] not found in blocklists")
            
            print(f"\nSearching for {len(priv_dom)} domains in blocklists...")
            for domain in priv_dom:
                found_in = search_domain_in_bloclists(domain)
                if found_in:
                    print(f"Domain [{domain}] found in: ", found_in)
                else:
                    print(f"Domain [{domain}] not found in blocklists")
            
            sys.stdout.flush()
        f.close()
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while analyzing suspicious emails: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__


def data_process(file_path, filename, output_file, output_file_block, private_info, outputfilebotnet, reports_directory):
    try:

        file_extension = filename.split('.')[-1]

        #If xlsx file, convert into csv
        if file_extension == 'xlsx':
            inp_f = file_path
            input_file = pd.read_excel(inp_f)
            file_path = file_path.replace("xlsx", "csv")
            input_file.to_csv(file_path, index=False)

            # Delete the xlsx file from the datasets directory
            pathlib.Path.unlink(inp_f)


        # Read CSV file and preprocess the data
        df = pd.read_csv(file_path, header=None, names=[
            'Office365URL', 'Field2', 'Field3', 'Field4', 'ReceivedTime', 'Field6', 'Field7', 'SenderAddress',
            'RecipientAddress', 'Subject', 'Field11', 'Field12', 'Field13', 'Field14', 'Field15', 'Field16',
            'Field17', 'Field18', 'Field19', 'Field20', 'Field21', 'Field22', 'Field23', 'Field24', 'Field25',
            'Field26', 'Field27', 'Field28', 'Field29', 'Field30', 'Field31', 'Field32', 'Field33', 'Field34',
            'Field35', 'Field36', 'Field37', 'Field38', 'Field39', 'Field40', 'Field41'])
        
        # Anomaly Detection - Detecting unusual email entries
        email_entry_col = 'SenderAddress'
        suspicious_emails = df[email_entry_col].value_counts()

        extract_unique_recipient_addresses(df, private_info)

        # Redirect print statements to the output file
        with open(output_file, 'w') as f:
            sys.stdout = f
            # Display Email Entry Access Frequency
            print("\nEmail Entry Access Frequency:")
            print(suspicious_emails)

            # Check for any email entries with unusually high access frequency
            threshold = 0  # Adjust threshold as needed
            print("\nSuspicious Email Entries (More than", threshold, "access attempts):")
            print(suspicious_emails[suspicious_emails > threshold])
            sys.stdout.flush()
        f.close()
        if suspicious_emails.empty:
            print("No email entry data found in the dataset.")
        else:
            # Identify the most suspicious email entry
            with open(output_file, 'a') as f:
                sys.stdout = f
                print("\n")
                most_suspicious_email = suspicious_emails[suspicious_emails > threshold].idxmax()
                print(f"Most suspicious email entry: {most_suspicious_email}")
                sys.stdout.flush()
            f.close()
                
            # Takes the suspicious email addresses with high access frequency as input for the script
            real_sus_emails = []
            real_sus_emails_dom = []
            found_emails = []
            found_domains = []

            with open(output_file_block, '+a') as f:
                sys.stdout = f
                sus_emails_in = suspicious_emails[suspicious_emails > threshold].index
                for email in sus_emails_in:
                    extracted_email = extract_emails(email)
                    if extracted_email not in real_sus_emails:
                        real_sus_emails.append(extracted_email)
                converted_list_of_emails = ' '.join(sus_emails_in)
                
                # Remove empty elements                
                real_sus_emails = [email for email in real_sus_emails if email != []]

                real_sus_emails = list(map(' '.join, real_sus_emails))
                real_sus_emails_dom = extract_domains(converted_list_of_emails)
                
                print("=========== Emails in Blocklists ===========")
                print(f"\nSearching for {len(real_sus_emails)} emails in blocklists...")
                for email in real_sus_emails:
                    found_in = search_email_in_blocklist(email)
                    if found_in:
                        print(f"  Email [{email}] found in: ", found_in)
                        found_emails.append(email)
                    else:
                        print(f"  Email [{email}] not found in blocklists")
                print("\n=========== Domains in Blocklists ===========")
                print(f"\nSearching for {len(real_sus_emails_dom)} domains in blocklists...")
                for domain in real_sus_emails_dom:
                    found_in = search_domain_in_bloclists(domain)
                    if found_in:
                        print(f"   Domain [{domain}] found in: ", found_in)
                        found_domains.append(domain)
                    else:
                        print(f"   Domain [{domain}] not found in blocklists")
                sys.stdout.flush()
            f.close()

            # Analyze all suspicious email entries
            for email in suspicious_emails[suspicious_emails > threshold].index:
                analyze_email_entry(df, email, output_file, found_emails, found_domains)

            # Analyze the most suspicious email entry
            # analyze_email_entry(df, most_suspicious_email)
                
            with open(outputfilebotnet, 'w') as f:
                sys.stdout = f
                analyze_suspicious_bot_attacks(df, outputfilebotnet, private_info, found_emails, found_domains)
            
            # Check if the outputfilebotnet is empty and if so, delete it
            check_empty_file_and_delete(outputfilebotnet)

            # Merge files and delete older for the production of a total report
            merge_files(output_file, output_file_block)
            delete_files(files=[output_file_block, private_info])

            if not os.path.exists(reports_directory):
                os.mkdir(reports_directory)
            shutil.move(output_file, reports_directory)
            shutil.move(outputfilebotnet, reports_directory)
                    
        sys.stdout = sys.__stdout__
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"An error occurred while processing the data: {e}")
    finally:
        # Restore sys.stdout to its original value to avoid interference in the Jupyter Notebook or interactive environments
        sys.stdout = sys.__stdout__