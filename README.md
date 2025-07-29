# NetScaler to Alteon Configuration Converter

This tool reads basic CLI configuration files from a NetScaler load balancer and converts them into Alteon basic CLI configurations.

In this second version, our goal is to develop a tool that can efficiently and repeatedly convert configurations such as backend servers, services, service groups, vServer health monitors, and SSL certificates, simplifying the process for mass configuration files from NetScaler.

Beyond aiding in mass configuration, this tool defines the structure for interpreting NetScaler configurations into Alteon, ensuring a smooth and accurate conversion.

## Prerequisites and Installation

### System Requirements
- Python 3.6 or higher
- pip (Python package installer)

### Installation Steps

1. **Clone or download the project** to your local machine

2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   
   Or install manually:
   ```bash
   pip install validators
   ```

3. **Verify installation** by running:
   ```bash
   python --version
   python -c "import validators; print('Dependencies installed successfully')"
   ```

## Note

Use this tool at your own risk. It is designed to assist with large sets of configurations but does not replace the expertise of a Network Engineer. This tool does not cover Layer 3, Layer 2, or Traffic Domain configurations.

This tool written and tested for CLI configuration of NetScaler version 14.X and Alteon version 33.0.X.

### Building Blocks of the System

- **main.py**: Feeds the NetScaler configuration file into the system.
- **printer_config.py**: Responsible for creating project files and formatting the configuration in Alteon CLI style.
- **NS_to_ALT.py**: Converts NetScaler class objects into Alteon class objects.
- **Alteon.py**: Defines the Alteon class, which contains other component classes.
- **real_server.py, group.py, service.py, virt.py, health_check.py**: Classes that define the various components of the Alteon class.
- **netscaler.py**: Reads the NetScaler configuration file and outputs dictionaries to be passed to NS_to_ALT.py.
- **materials.py**: Contains functions and attributes that ensure integrity.
- **ssl-policy.py**: A placeholder for future versions of this tool, which will include SSL attributes.

### Functionality of this tool

main.py triggers printer_config.py (by getting the file path), starts a new project, and initiates the conversion method.

netscaler.py processes the configuration file and outputs a dictionary for NS_to_ALT.py, which handles the returned dictionary and converts it into an Alteon object.

Once we have the Alteon object, we print the configuration using the getters of the Alteon class.


### Supported Features
#### Note: NetScaler feature names are in parentheses.

- **Real Server** (Server)
- **FQDN Server** (FQDN)
- **Group** (N/A)
- **Load Balancing Algorithms**: Round-Robin, Least Connection, SourceIPHASH, Least Response Time, Least Bandwidth
- **Persistence Configurations**: SOURCEIP, COOKIEINSERT, SSLSESSION
- **Service** (Service / Service Group)
- **VIRT** (Vserver)
- **FTP Support**: Control and Data Port
- **Redirect from HTTP to HTTPS** (Response Policy), **XFF Insert** (USIP)
- **Health Checks**: TCP, UDP, ICMP, ARP, HTTP/S
- **Certificate and Keys Conversion**: Handled by an additional script

## Tool to Convert Certificates and Keys to Alteon

### Note: This is an additional simple tool and not part of the main system.

1. Edit the file `netscalet_to_alt_cert_migration.py` and change the path to the text file where the results will be saved in the parameter `CertsConfForAlteon`.
2. Edit the file `netscalet_to_alt_cert_migration.py` and change the path to the certificate files exported from NetScaler in the parameter `cert_dir`.
3. Run the script: `python netscalet_to_alt_cert_migration.py`.
4. Copy the content of the resulting text file.
5. Connect to the Alteon using SSH.
6. Type `verbose 0` to enter the insert configuration mode.
7. Paste the content of the text file.
8. Type `verbose 1` to exit the insert configuration mode.
9. Type `apply` and then `save`.

## How to Use the Converter Tool

**Prerequisites**: Make sure you have completed the [Prerequisites and Installation](#prerequisites-and-installation) steps above.

1. Copy the project to your local machine.
2. Run `main.py`. You will be asked to provide the path to the NetScaler configuration file.
3. **Tip**: Place the configuration file in the same folder as the script to avoid path issues.
4. Run the script and review the results.
5. Running the script will create a folder inside the project folder with four files:
    - `handled_lines.txt`: Lines from the NetScaler configuration that have been converted.
    - `unhandled_lines.txt`: Lines from the NetScaler configuration ignored by the script.
    - `unhandled_flags.txt`: Lines from the NetScaler configuration that were processed but contained unsupported features.
    - `alteon_config.txt`: The resulting Alteon configuration.
6. Copy the content of `alteon_config.txt`.
7. Connect to the Alteon using SSH.
8. Type `verbose 0` to enter insert configuration mode.
9. Paste the content of the text file.
10. Type `verbose 1` to exit insert configuration mode.
11. Type `apply` and then `save`.

### Not supported

- Layer 2 configuration
- Layer 3 configuration
- Support for Traffic Domain
- support TLS policies (Currently there is default ssl policy supports TLSv1.2 and TLSv1.3)
- support for HTTP options
- GSLB configurations


### Roadmap
#### version 3
- SSL policies 
- TCP Profile (Currently there is default tcp policy supports for keepalive feature)
- More HTTP features and http profile
- HTTP-3
- Support for Traffic Domain
- Layer 7 policies support




For any concern, feedback, request and etc.. you always welcome to speak with me : tomerel@radware.com
