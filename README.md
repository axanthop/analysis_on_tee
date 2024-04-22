
# Analysis on tee

1) Run the main.py file from your terminal with the directory path of your file(s) as an argument.

2) The program triggers the respective script based on the type of file(s) included in the chosen directory (CSV, xlsx, Txt and JSON). Each type of file gets processed in a different way from the 3 different analysers (bells_tee_analyser.py, dpc_tee_analyser.py and exus_tee_analyser) that extract the detailed reports for IPs or emails.

3) The triggered analyser reads and cleans the data file to start the information extraction procedure. More specifically, a pattern identification procedure is taking place for the extraction of CTI. Information such as the more suspicious IPs and their specific action (e.g. ports that 'hit') and details of Emails such as Sender Address or Subject are included in the generated report.

4) After the CTI extraction, the values of interest (i.e. IPs and emails) are also checked for correlation with information in external sources, which are blocklists found on the web. The correlation procedure is accomplished through a function that takes all the IPs and emails and correlates them with the information in the blocklists.

5) Another procedure that takes place is the extraction of private information from the data file. As private information we refer to the unique IPs or Emails that can be found as recipient. If the private information found also in Sender (potentially bot-related attacks), the program analyzes each entry with the same function of information extraction procedure.

6) After the information extraction, the private values of interest (i.e. private IPs and emails) found in Sender are also checked for correlation with information of the blocklists found on the web using the same function but with the private IPs or emails found in Sender being the input in this case.

7) There is a Flag indication/mark that is added to the initial entry analysis of the values of interest (i.e. IPs and emails and private IPs and emails) that gives the opportunity to the provider to be directly informed about the existence of a specific IP and email in the external sources (i.e. blocklists found on the web) across with the initial information extraction procedure.

8) The final pair of procedures is the correlation between the providers, both for the 2 types of CTI extracted (i.e. private and non private). This correlation uses a function that takes the information of both providers and compare them in order to generate a txt file as a report including whether the values of interest found in each other's data files. The Flag indication is also in use here with the addition of ‘revealing’ the information if found.

9) Once the correlation procedures are over, the program produces a txt file as a report for every file in the given directory with the output of both procedures (CTI extraction & correlation procedure) for each of the 2 types of CTI (private and non private) along with the correlation results between the providers. So, there is a part of the initial report that contains the features of the extracted IPs or emails and domains and there is also a part of the findings indicating whether the extracted IPs or emails and domains exist on the blocklists or not.

10) The reports are stored in a directory inside the project called "Reports" which consists of 3 other directories that each of them refers to the repsective provider and contains the txt files that are generated from each analyser with the date that has been produced.
