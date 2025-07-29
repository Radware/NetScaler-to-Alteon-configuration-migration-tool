"""Script provided by: Chitrangkumar Patel <chitrangkumar.patel@radware.com> | Radware PS
Edited by tomer elmoalem | Radware ADC ASE team
Notes:
-	The script is written in Python 3
-	The script uses the os module which is part of the standard library (no need to install it separately)
-   Exporting the certificates form Netscaler LB should be without passphrase

Prerequisites:
-	Install the latest Python 3.X
-	Export certificates and keys that need to be imported to the Alteon to the specific folder (“cert_dir”  variable)
-	Before running the script, please change the below variables:
cert_dir  - a path where you place the certificates and keys
CertsConfForAlteon – a path where Alteon config file will be created.

-  provide netscaler configuration to link between certificate and keys

"""


import os
#Change the destination file conf
CertsConfForAlteon = open(r'C:\path\to\export\result\nsconfig\ssl\FILE.txt', "w")

#Change the source of the certs directory
cert_dir = r"C:\path\to\certificates\files\\"

#add ssl certKey name_of_cert_and_key -cert name_of_cert_file.crt -key name_of_key_file.key
#read netscaler configuration and search for the above pattern, than

#

arr = os.listdir(cert_dir)
for i in arr:
    if i.endswith('.pem') or i.endswith('.crt') or i.endswith('.key')or i.endswith('.cert'):


        #print(i)
        file = open(cert_dir + i)

        file_contents = file.read()
        #print(file_contents)

        search_cert_word = "BEGIN CERTIFICATE"
        search_key_word = "BEGIN RSA PRIVATE KEY"

        if search_cert_word in file_contents:
            print(i + " is a CERTIFICATE")
            CertsConfForAlteon.write("/c/slb/ssl/certs/cert " + i.split(".")[0] + "\n")
            CertsConfForAlteon.write("/c/slb/ssl/certs/import cert " + i.split(".")[0] + " text" + "\n")
            CertsConfForAlteon.write(file_contents)
            CertsConfForAlteon.write("\n")

        elif search_key_word in file_contents:
            print(i + " is a KEY")
            CertsConfForAlteon.write("/c/slb/ssl/certs/key " + i.split(".")[0] + "\n")
            CertsConfForAlteon.write("/c/slb/ssl/certs/import key " + i.split(".")[0] + " text" + "\n")
            CertsConfForAlteon.write(file_contents)
            CertsConfForAlteon.write("\n")