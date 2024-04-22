import os
import sys
import pathlib
import shutil
from datetime import date
from utils import get_files_from_directory, get_filename, get_file_details, increase_by_1, delete_files
from providers_correlation import providers_correlation_process

def ensure_directory_exists(path):
    """Ensure the directory exists, and if not, create it."""
    os.makedirs(path, exist_ok=True)

def data_process(file_path, filename, output_file):
    try:
        # Ensure the Reports directory exists before proceeding
        reports_dir = os.path.dirname(output_file)
        ensure_directory_exists(reports_dir)

    except Exception as e:
        print(f"An error occurred while processing the data: {e}")
    finally:
        # Restore sys.stdout to its original value
        sys.stdout = sys.__stdout__

# Assuming your utils and other required imports are defined elsewhere

try:
    directory = sys.argv[1]
    directory_files = get_files_from_directory(directory)
    ensure_directory_exists("./Reports/")
    files_count = 0
    for file in directory_files:
        file_path, filename, realfile, file_extension = get_file_details(directory, file)
        current_date = date.today()
        output_file = "./Reports/" + str(current_date) + "_" + realfile + "_analysis.txt"
        output_file_block = "./Reports/" + str(current_date) + "_" + realfile + "_analysis_blocklists.txt"
        private_info = "./Reports/" + str(current_date) + "_" + realfile + "_private_info.txt"
        outputfilebotnet = "./Reports/" + str(current_date) + "_" + realfile + "_analysis_private_botnet.txt"


        if file_extension in ['csv', 'xlsx']:
            from dpc_tee_analyser import data_process
            files_count = increase_by_1(files_count)
            reports_directory_prov3 = "./Reports/"+filename.split('.')[0]
            data_process(file_path, filename, output_file, output_file_block, private_info, outputfilebotnet,
                         reports_directory_prov3)
        elif file_extension == 'txt':
            from bells_tee_analyser import data_process
            files_count = increase_by_1(files_count)
            bells_correlaiton_file = "./Reports/Provider_8Bells.txt"
            private_bells_correlation_file = "./Reports/Private_Provider_8Bells.txt"
            prov2_message = "8BELLS"
            reports_directory_prov2 = "./Reports/"+filename.split('.')[0]
            data_process(file_path, filename, output_file, output_file_block, private_info, outputfilebotnet,
                         bells_correlaiton_file, private_bells_correlation_file, reports_directory_prov2)
        elif file_extension == 'json':
            from exus_tee_analyser import data_process
            files_count = increase_by_1(files_count)
            exus_correlation_file = "./Reports/Provider_Exus.txt"   
            private_exus_correlation_file = "./Reports/Private_Provider_Exus.txt"
            prov1_message = "EXUS"
            reports_directory_prov1 = "./Reports/"+filename.split('.')[0]
            data_process(file_path, filename, output_file, output_file_block, private_info, outputfilebotnet, 
                         exus_correlation_file, private_exus_correlation_file, reports_directory_prov1)
        else:
            print(f"Unsupported file extension for {filename}")
            continue

        # data_process(file_path, filename, output_file, output_file_block, private_info, outputfilebotnet)
        print(f"{filename} file produced the reports")

    if files_count > 1:
        # Correlation between providers
        provider1 = get_filename(exus_correlation_file)
        provider2 = get_filename(bells_correlaiton_file)
        private_provider1 = get_filename(private_exus_correlation_file)
        private_provider2 = get_filename(private_bells_correlation_file)
        providers_correlation_file = "./Reports/" + provider1 + "_with_" + provider2 + "_correlation.txt"
        providers_correlation_file_alt = "./Reports/" + provider2 + "_with_" + provider1 + "_correlation.txt"
        private_providers_correlation_file = "./Reports/" + private_provider1 + "_with_" + private_provider2 + "_correlation.txt"
        private_providers_correlation_file_alt = "./Reports/" + private_provider2 + "_with_" + private_provider1 + "_correlation.txt"

        providers_correlation_process(exus_correlation_file, prov1_message, bells_correlaiton_file, prov2_message,
                                       providers_correlation_file)
        providers_correlation_process(private_exus_correlation_file, prov1_message, private_bells_correlation_file,
                                      prov2_message, private_providers_correlation_file)
        
        providers_correlation_process(bells_correlaiton_file, prov2_message, exus_correlation_file, prov1_message,
                                      providers_correlation_file_alt)
        providers_correlation_process(private_bells_correlation_file, prov2_message, private_exus_correlation_file,
                                      prov1_message, private_providers_correlation_file_alt)
        
        # Move files to each provider's directory produce the final reports
        shutil.move(providers_correlation_file, reports_directory_prov1)
        shutil.move(private_providers_correlation_file, reports_directory_prov1)

        shutil.move(providers_correlation_file_alt, reports_directory_prov2)
        shutil.move(private_providers_correlation_file_alt, reports_directory_prov2)

        # Delete the files that produced for help
        # in order to generate the final correlation txt
        delete_files(files=[exus_correlation_file, bells_correlaiton_file,
                           private_exus_correlation_file, private_bells_correlation_file])

except Exception as e:
    print(f"An error occurred while processing the data: {e}")
