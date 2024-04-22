
# Analysis on tee

1) Run the main.py file from your terminal with the directory path of your file(s) as an argument.

2) The program triggers the respective script based on the type of file(s) included in the chosen directory (CSV, xlsx, Txt and JSON). Each type of file gets processed in a different way from the 3 different analysers (bells_tee_analyser.py, dpc_tee_analyser.py and exus_tee_analyser) that extract the detailed reports for IPs or emails.

3) The triggered analyser reads and cleans the data file to start the information extraction procedure. More specifically, a pattern identification procedure is taking place for the extraction of CTI. Information such as the more suspicious IPs and their specific action (e.g. ports that 'hit') and details of Emails such as Sender Address or Subject are included in the generated report.

4) Another procedure that takes place is the extraction of private information from the data file. As private information we refer to the unique IPs or Emails that can be found as recipient. If the private information found also in Sender (potentially bot-related attacks), the program analyzes each entry with the same function of information extraction procedure.

5) The final pair of procedures is the correlation between the providers, both for the 2 types of CTI extracted (i.e. private and non private). This correlation uses a function that takes the information of both providers and compare them in order to generate a txt file as a report including whether the values of interest found in each other's data files. The Flag indication is in use here with ‘revealing’ of information if found.

6) There is a Flag indication/mark that is added to the values of interest (i.e. IPs and emails and private IPs and emails) that take part in the comparison process that gives the opportunity to the provider to be directly informed about the specific IP and email.

7) Once the correlation procedures are over, the program produces a txt file as a report for every file in the given directory with the output of CTI extraction for each of the 2 types of CTI (private and non private) along with the correlation results between the providers. So, the initial report contains the features of the extracted IPs or emails and domains.

8) The reports are stored in a directory inside the project called "Reports" which generates a folder for each provider and contains the txt files that are generated from each analyser with the date that has been produced.
