import os
from datetime import date
from materials import *

def create_conversion_project(netscaler_config_file):
    """
    Sets up a new conversion project with organized structure.

    Args:
        netscaler_config_file (str): Name of the Netscaler configuration file.
    """

    # Get today's date for the project folder
    today = date.today().strftime("%Y-%m-%d")

    # Create the base project folder
    project_folder = f"{today}_{netscaler_config_file.strip('.txt')}"
    os.makedirs(project_folder, exist_ok=True)

    # Paths for generated files within the project folder
    python_config_path = os.path.join(project_folder, "alteon_config.txt")
    unhandled_lines_path = os.path.join(project_folder, "unhandled_lines.txt")
    handled_lines_path = os.path.join(project_folder, "handled_lines.txt")
    unhandled_flags_path = os.path.join(project_folder, "unhandled_flags.txt")
    alteon_config_file = os.path.join(project_folder, "alteon_config.txt")

    # Copy the Netscaler config file (replace with your copy logic)
    # ...

    # Create output files with initial content
    with open(python_config_path, "w") as f:
        f.write(" ")

    with open(unhandled_lines_path, "w") as f:
        f.write("# Lines from Netscaler config that could not be converted\n")

    with open(handled_lines_path, "w") as f:
        f.write("# Successfully converted lines from Netscaler config\n")

    with open(unhandled_flags_path, "w") as f:
        f.write("# Flags on converted lines that require attention\n")

    with open(alteon_config_file, "w") as f:
        f.write(" ")

    # Create and return a dictionary of filenames
    file_paths = {
        "alteon_config": python_config_path,
        "unhandled_lines": unhandled_lines_path,
        "handled_lines": handled_lines_path,
        "unhandled_flags": unhandled_flags_path,
        "alteon_config_file" : alteon_config_file
    }

    print(f"Conversion project created: {project_folder}")
    return file_paths


def write_to_alteon_config(path,line):
    with open(rf"{path}", "a") as f:
        f.write(line + "\n")


def write_to_unhandled_lines(ns_config_file, handled_lines_file, path):
    ns_config_lines = []
    handled_config_lines = []
    unhandled_config_lines = []

    with open(rf"{ns_config_file}", "r") as file:
        ns_config_lines = file.readlines()

    with open(rf"{handled_lines_file}", "r") as hnd_file:
        handled_config_lines = hnd_file.readlines()

    for line in ns_config_lines:
        if line in handled_config_lines:
            continue
        else:
            unhandled_config_lines.append(line)

    #print(f"Debug: Writing {len(unhandled_config_lines)} unhandled lines to {path}")

    with open(rf"{path}", "a") as f:
        for line in unhandled_config_lines:
            f.write(line)
            f.flush()

    #print("Debug: Write operation completed.")


def write_to_handled_lines(path,line):
    with open(rf"{path}", "a") as f:
        f.write(line)


def write_to_unhandled_flags(path,virt_or_service_name, flag ,reason):
    with open(rf"{path}", "a") as f:
        f.write(f"Expection on :{virt_or_service_name} Flag: {flag} | reason: {reason}\n")


def uniquify_lines_in_file(path):
    try:
        with open(rf"{path}", "r") as f:
            lines = f.readlines()

        unique_lines = set(lines)

        with open(rf"{path}", "w") as f:
            f.writelines(unique_lines)
    except FileNotFoundError:
        pass


def print_real_server(real_alteon_object):
    "Get Alteon Object and print Real servers Alteon CLI configuration according to the Object recived"
    name = real_alteon_object.get_name()
    ip_address = real_alteon_object.get_ip_address()
    state = real_alteon_object.get_state()
    comment = real_alteon_object.get_comment()
    ip_version = real_alteon_object.get_ip_version().strip("ip")
    add_ports_lst = real_alteon_object.get_list_add_ports() #addport
    if not comment:
        line = f'/c/slb/real {name}/{state}/ipver {ip_version}/rip {ip_address}\n'
    else:
        line = f'/c/slb/real {name}/{state}/ipver {ip_version}/rip {ip_address}/name "{comment}"\n'
    if len(add_ports_lst) > 0 and comment:
        line = f"/c/slb/real {name}/{state}/ipver {ip_version}/rip {ip_address}/name '{comment}'/addport {'addport '.join(add_ports_lst)}\n"
    if len(add_ports_lst) > 0 and not comment:
        line = f"/c/slb/real {name}/{state}/ipver {ip_version}/rip {ip_address}/addport {'addport '.join(add_ports_lst)}\n"
    return line


def print_fqdn_server(fqdn_alteon_object):
    "Get Alteon Object and print FQDN servers Alteon CLI configuration according to the Object recived"
    fqdn_id = fqdn_alteon_object.get_fqdn_id()
    fqdn_domain = fqdn_alteon_object.get_fqdn_domain()
    state = fqdn_alteon_object.get_state()
    ip_version = fqdn_alteon_object.get_ip_version().strip("ip")
    ttl = fqdn_alteon_object.get_ttl()
    fqdn_real_template = fqdn_alteon_object.get_fqdn_real_template()
    add_port = fqdn_alteon_object.get_add_port()

    if fqdn_real_template:
        lines = f"""/c/slb/adv/fqdnreal {fqdn_id}/name {fqdn_domain}/ttl {ttl}/group grp_fqdn_{fqdn_real_template}/tmpl {fqdn_real_template}/{state}
            /c/slb/real {fqdn_id}/dis/ipver {ip_version}/rip 1.1.1.1 
            /c/slb/group grp_fqdn_{fqdn_id}/ipver {ip_version}/add {fqdn_id}\n"""
        if add_port:
            lines = f"""/c/slb/adv/fqdnreal {fqdn_id}/name {fqdn_domain}/ttl {ttl}/group grp_fqdn_{fqdn_real_template}/tmpl {fqdn_real_template}/{state}
                        /c/slb/real {fqdn_id}/dis/ipver {ip_version}/rip 1.1.1.1/addport {add_port}
                        /c/slb/group grp_fqdn_{fqdn_id}/ipver {ip_version}/add {fqdn_id}\n"""

    else:
        lines = f"""/c/slb/adv/fqdnreal {fqdn_id}/name {fqdn_domain}/ttl {ttl}/group grp_fqdn_{fqdn_id}/tmpl {fqdn_id}/{state}
        /c/slb/real {fqdn_id}/dis/ipver {ip_version}/rip 1.1.1.1
        /c/slb/group grp_fqdn_{fqdn_id}/ipver {ip_version}/add {fqdn_id}\n"""
    return lines


def print_hc(hc_alteon_object):
    "Get Alteon Object and print Health Checks Alteon CLI configuration according to the Object recived"
    if hc_alteon_object.get_monitor_type() == "HTTP":
        http_id = hc_alteon_object.get_http_id()
        description = hc_alteon_object.get_description()
        https = hc_alteon_object.get_https()
        destination_port = hc_alteon_object.get_destination_port()
        ip_version = hc_alteon_object.get_ip_version()
        destination_ip = hc_alteon_object.get_destination_ip()
        invert_result = hc_alteon_object.get_invert_result()
        transparent_health_check = hc_alteon_object.get_transparent_health_check()
        connection_termination = hc_alteon_object.get_connection_termination()
        always_perform_health_check = hc_alteon_object.get_always_perform_health_check()
        method = hc_alteon_object.get_method()
        hostname = hc_alteon_object.get_hostname()
        path = hc_alteon_object.get_path()
        http2 = hc_alteon_object.get_http2()
        header = hc_alteon_object.get_header()
        body = hc_alteon_object.get_body()
        authentication = hc_alteon_object.get_authentication()
        proxy_request = hc_alteon_object.get_proxy_request()
        expected_return_codes = hc_alteon_object.get_expected_return_codes()
        return_string_type = hc_alteon_object.get_return_string_type()
        overload_type = hc_alteon_object.get_overload_type()
        interval = hc_alteon_object.get_interval()
        retries_to_failure = hc_alteon_object.get_retries_to_failure()
        retries_to_restore = hc_alteon_object.get_retries_to_restore()
        response_timeout = hc_alteon_object.get_response_timeout()
        checks_interval_on_downtime = hc_alteon_object.get_checks_interval_on_downtime()
        expected_return_string = hc_alteon_object.get_expected_return_string()

        # Define the attributes and their corresponding values
        attributes = {
            "name": description,
            "dport": destination_port,
            "dest": destination_ip,
            "invert": invert_result,
            "transp": transparent_health_check,
            "inter": interval,
            "retry": retries_to_failure,
            "restr": retries_to_restore,
            "timeout": response_timeout,
            "downtime": checks_interval_on_downtime,
            "connterm": connection_termination,
            "ssl": https
        }

        # Start the configuration string with the initial line
        config_lines = [f"/c/slb/advhc/health {http_id} HTTP"]

        # Iterate through the attributes and append if the value is valid
        for attr, value in attributes.items():
            if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
                config_lines.append(f"    {attr} {value}")

        # Add additional HTTP specific attributes
        http_specific_attributes = {
            "method": method,
            "host": hostname,
            "path": path,
            "header": header,
            "body": body
        }
        http_specific_lines = [f"/c/slb/advhc/health {http_id} HTTP/http"]

        for attr, value in http_specific_attributes.items():
            if value and str(value).strip():
                http_specific_lines.append(f"    {attr} {value}")

        if expected_return_codes:
            http_specific_lines.append(f"    response {expected_return_codes} incl {expected_return_string}")

        # Join the configuration lines into a single string
        config_string = "\n".join(config_lines + http_specific_lines)

        # Print the configuration string
        return config_string

    # Example usage

    if hc_alteon_object.get_monitor_type() == "TCP":
        tcp_id = hc_alteon_object.get_tcp_id()
        description = hc_alteon_object.get_description()
        ip_version = hc_alteon_object.get_ip_version()
        destination_port = hc_alteon_object.get_destination_port()
        invert_result = hc_alteon_object.get_invert_result()
        transparent_health_check = hc_alteon_object.get_transparent_health_check()
        connection_termination = hc_alteon_object.get_connection_termination()
        always_perform_health_check = hc_alteon_object.get_always_perform_health_check()
        interval = hc_alteon_object.get_interval()
        retries_to_failure = hc_alteon_object.get_retries_to_failure()
        retries_to_restore = hc_alteon_object.get_retries_to_restore()
        response_timeout = hc_alteon_object.get_response_timeout()
        checks_interval_on_downtime = hc_alteon_object.get_checks_interval_on_downtime()

        # Define the attributes and their corresponding values
        attributes = {
            "name": description,
            "dport": destination_port,
            "invert": invert_result,
            "transp": transparent_health_check,
            "connterm": connection_termination,
            "inter": interval,
            "retry": retries_to_failure,
            "restr": retries_to_restore,
            "timeout": response_timeout,
            "downtime": checks_interval_on_downtime
        }

        # Start the configuration string with the initial line
        config_lines = [f"/c/slb/advhc/health {tcp_id} TCP"]

        # Iterate through the attributes and append if the value is valid
        for attr, value in attributes.items():
            if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
                config_lines.append(f"    {attr} {value}")

        # Join the configuration lines into a single string
        config_string = "\n".join(config_lines)

        # Print the configuration string
        return config_string

    if hc_alteon_object.get_monitor_type() == "ARP":
        arp_id = hc_alteon_object.get_arp_id()
        mon_name = hc_alteon_object.get_name()
        description = hc_alteon_object.get_description()
        destination_ip = hc_alteon_object.get_destination_ip()
        invert_result = hc_alteon_object.get_invert_result()
        interval = hc_alteon_object.get_interval()
        retries_to_failure = hc_alteon_object.get_retries_to_failure()
        retries_to_restore = hc_alteon_object.get_retries_to_restore()
        response_timeout = hc_alteon_object.get_response_timeout()
        check_interval_downtime = hc_alteon_object.get_check_interval_downtime()
        # Define the attributes and their corresponding values
        attributes = {
            "name": description,
            "dest": destination_ip,
            "invert": invert_result,
            "inter": interval,
            "retry": retries_to_failure,
            "restr": retries_to_restore,
            "timeout": response_timeout,
            "downtime": check_interval_downtime
        }


        # Start the configuration string with the initial line
        config_lines = [f"/c/slb/advhc/health {mon_name} ARP"]

        # Iterate through the attributes and append if the value is valid
        for attr, value in attributes.items():
            if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
                config_lines.append(f"    {attr} {value}")

        # Join the configuration lines into a single string
        config_string = "\n".join(config_lines)

        # Print the configuration string
        return config_string

    if hc_alteon_object.get_monitor_type() == "UDP":
        udp_id = hc_alteon_object.get_udp_id()
        description = hc_alteon_object.get_description()
        destination_port = hc_alteon_object.get_destination_port()
        ip_version = hc_alteon_object.get_ip_version()
        destination_ip = hc_alteon_object.get_destination_ip()
        invert_result = hc_alteon_object.get_invert_result()
        transparent_health_check = hc_alteon_object.get_transparent_health_check()
        padding_to_64_bytes = hc_alteon_object.get_padding_to_64_bytes()
        interval = hc_alteon_object.get_interval()
        retries_to_failure = hc_alteon_object.get_retries_to_failure()
        retries_to_restore = hc_alteon_object.get_retries_to_restore()
        response_timeout = hc_alteon_object.get_response_timeout()
        checks_interval_on_downtime = hc_alteon_object.get_checks_interval_on_downtime()
        # Define the attributes and their corresponding values
        attributes = {
            "name": description,
            "dport": destination_port,
            "dest": f"{ip_version.strip('IPv')} {destination_ip}" if ip_version and destination_ip else destination_ip,
            "invert": invert_result,
            "transp": transparent_health_check,
            "inter": interval,
            "retry": retries_to_failure,
            "restr": retries_to_restore,
            "timeout": response_timeout,
            "downtime": checks_interval_on_downtime
        }

        # Start the configuration string with the initial line
        config_lines = [f"/c/slb/advhc/health {udp_id} UDP"]

        # Iterate through the attributes and append if the value is valid
        for attr, value in attributes.items():
            if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
                config_lines.append(f"    {attr} {value}")

        # Join the configuration lines into a single string
        config_string = "\n".join(config_lines)

        # Print the configuration string
        return config_string

    if hc_alteon_object.get_monitor_type() == "ICMP":
        icmp_id = hc_alteon_object.get_icmp_id()
        description = hc_alteon_object.get_description()
        ip_version = hc_alteon_object.get_ip_version()
        destination_ip = hc_alteon_object.get_destination_ip()
        invert_result = hc_alteon_object.get_invert_result()
        transparent_health_check = hc_alteon_object.get_transparent_health_check()
        interval = hc_alteon_object.get_interval()
        retries_to_failure = hc_alteon_object.get_retries_to_failure()
        retries_to_restore = hc_alteon_object.get_retries_to_restore()
        response_timeout = hc_alteon_object.get_response_timeout()
        checks_interval_on_downtime = hc_alteon_object.get_checks_interval_on_downtime()
        # Define the attributes and their corresponding values
        attributes = {
            "name": description,
            "dest": f"{ip_version} {destination_ip}" if ip_version and destination_ip else destination_ip,
            "invert": invert_result,
            "transp": transparent_health_check,
            "inter": interval,
            "retry": retries_to_failure,
            "restr": retries_to_restore,
            "timeout": response_timeout,
            "downtime": checks_interval_on_downtime
        }

        # Start the configuration string with the initial line
        config_lines = [f"/c/slb/advhc/health {icmp_id} ICMP"]

        # Iterate through the attributes and append if the value is valid
        for attr, value in attributes.items():
            if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
                config_lines.append(f"    {attr} {value}")

        # Join the configuration lines into a single string
        config_string = "\n".join(config_lines)

        # Print the configuration string
        return config_string




def pre_define_tcp_pol():
    str = """
    /c/slb/tcppol keep_alive_tcp_pol
 	ena
    /c/slb/tcppol keep_alive_tcp_pol/keepaliv
 	ena
    """
    return str

def pre_define_ssl_pol():
    str = """
    /c/slb/ssl/sslpol default_ssl_pol
    convert disabled
 	ena
    /c/slb/ssl/sslpol default_ssl_pol/backend
 	ssl enabled
    """
    return str

def print_group(group_alteon_object):
    "Get Alteon Object and print group Alteon CLI configuration according to the Object recived"
    group_id = group_alteon_object.get_group_id()
    description = group_alteon_object.get_description()
    group_type = group_alteon_object.get_group_type()
    ip_version = group_alteon_object.get_ip_version().strip("ip")
    slb_metric = group_alteon_object.get_slb_metric()
    health_check = group_alteon_object.get_health_check()
    slow_start = group_alteon_object.get_slow_start()
    group_down_threshold = group_alteon_object.get_group_down_threshold()
    group_restored_threshold = group_alteon_object.get_group_restored_threshold()
    backup = group_alteon_object.get_backup()
    ids_group = group_alteon_object.get_ids_group()
    ids_chain = group_alteon_object.get_ids_chain()
    group_flood = group_alteon_object.get_group_flood()
    real_port_metric = group_alteon_object.get_real_port_metric()
    alert_on_server_failure_threshold = group_alteon_object.get_alert_on_server_failure_threshold()
    workload_manager_id = group_alteon_object.get_workload_manager_id()
    dsr_vip_health_check = group_alteon_object.get_dsr_vip_health_check()
    operator_access = group_alteon_object.get_operator_access()
    health_check_formula = group_alteon_object.get_health_check_formula()
    overload_overflow_exception = group_alteon_object.get_overload_overflow_exception()
    radius_group_secret = group_alteon_object.get_radius_group_secret()
    real_servers = [real['service_member'] for real in group_alteon_object.list_all_real_servers()]
    real_servers = get_unique_values(real_servers)
    # Define the attributes and their corresponding values
    attributes = {
        "ipver": ip_version.strip("IP"),
        "metric": slb_metric,
        "health": health_check,
        "slowstart": slow_start,
        "downthresh": group_down_threshold,
        "restthresh": group_restored_threshold,
        "backup": backup,
        "idsgroup": ids_group,
        "idschain": ids_chain,
        "flood": group_flood,
        "portmetric": real_port_metric,
        "alertthresh": alert_on_server_failure_threshold,
        "wloadmgr": workload_manager_id,
        "dsrhc": dsr_vip_health_check,
        "opaccess": operator_access,
        "hcformula": health_check_formula,
        "overflowexcp": overload_overflow_exception,
        "radiussec": radius_group_secret
    }

    # Start the configuration string with the initial line
    config_lines = [f"/c/slb/group {group_id}"]

    # Iterate through the attributes and append if the value is valid
    for attr, value in attributes.items():
        if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
            config_lines.append(f"    {attr} {value}")

    # Add real servers
    for server in real_servers:
        config_lines.append(f"    add {server}")

    # Add description if present
    if description and str(description).strip():
        config_lines.append(f"    name \"{description}\"")

    # Join the configuration lines into a single string
    config_string = "\n".join(config_lines)

    # Print the configuration string
    return config_string


def print_virt(virt_alteon_object):
    """Get Alteon Object and print VIRT Alteon CLI configuration according to the Object recived
    Get Alteon Object and print service Alteon CLI configuration according to the Object recived"""
    virtual_server_id = virt_alteon_object.get_virtual_server_id()
    description = virt_alteon_object.get_description()
    ip_version = virt_alteon_object.get_ip_version().strip("IP")
    if validate_ipv4(virt_alteon_object.get_ip_address()) or validate_ipv6(virt_alteon_object.get_ip_address()):
        ip_address = virt_alteon_object.get_ip_address()
    enabled = virt_alteon_object.get_enabled()
    services_ids = virt_alteon_object.list_all_service_ids()
    # Start the configuration string with the initial line
    config_lines = [f"/c/slb/virt {virtual_server_id}"]

    # Add the enable line if the virtual server is enabled
    if enabled:
        config_lines.append("    ena")

    # Define the attributes and their corresponding values
    attributes = {
        "ipver": ip_version,
        "vip": ip_address,
        "vname": description,
        "rtsrcmac": "ena"
    }

    # Iterate through the attributes and append if the value is valid
    for attr, value in attributes.items():
        if value and str(value).strip():  # Check if value is not None, not empty, and not just spaces
            config_lines.append(f"    {attr} {value}")

    # Join the configuration lines into a single string
    config_string = "\n".join(config_lines)

    # Print the configuration string
    if ip_address:
        return config_string
    else:
        return ""



def print_service(service_alteon_object):
    action = service_alteon_object.get_action()
    redirect_str = service_alteon_object.get_redirect_string()
    service_id = service_alteon_object.get_service_id()
    application = service_alteon_object.get_application()
    service_port = service_alteon_object.get_service_port()
    protocol = service_alteon_object.get_protocol()
    group_id = service_alteon_object.get_group_id()
    real_server_port = service_alteon_object.get_real_server_port()
    session_timeout = service_alteon_object.get_session_timeout() ####################################
    if isinstance(service_alteon_object.get_virt_assoiciate(), str):
        virt_assoiciate = service_alteon_object.get_virt_assoiciate()
    else:
        virt_assoiciate = service_alteon_object.get_virt_assoiciate().get_virtual_server_id()


    # Basic service configuration
    line = f'/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}\n'
    line += f'    group {group_id}\n    rport {real_server_port}'

    if protocol and protocol.lower() != "tcp":
        line += f'\n    protocol {protocol.lower()}\n'

    if session_timeout:
        line += f'\n    tmout {session_timeout.lower()}\n'

    # Handle redirect action
    if action == "redirect":
        line = f'/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}\n'
        line += f'    action {action}\n    redirect {redirect_str}'

    # Handle FTP special case
    if application.lower() == 'ftp' and service_port == "21":
        line = f'/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}\n'
        line += f'    group {group_id}\n    rport {real_server_port}\n'
        line += f'    ftpp ena\n    dataport 20'

        # Add additional service for FTP-Data on port 20
        line += f'\n/c/slb/virt {virt_assoiciate}/service 20 ftp-data\n'
        line += f'    group {group_id}\n    rport 0'

    # Additional configurations
    ssl_certificate = service_alteon_object.get_ssl_certificate()
    ssl_policy_name = service_alteon_object.get_ssl_policy_name()
    insert_xff = service_alteon_object.get_insert_xff()
    pip_mode = service_alteon_object.get_pip()
    persist_cookie_insert = service_alteon_object.get_persist_cookie_insert()

    if ssl_certificate:
        line += f'\n/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}/ssl\n'
        line += f'    srvrcert {ssl_certificate}'
    if ssl_policy_name:
        line += f'\n/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}/ssl\n'
        line += f'    sslpol {ssl_policy_name}'
    if insert_xff:
        line += f'\n/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}/http\n'
        line += f'    xforward {insert_xff}'
    if pip_mode:
        line += f'\n/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}/pip\n'
        line += f'    mode {pip_mode}'
    if persist_cookie_insert:
        line += f'\n/c/slb/virt {virt_assoiciate}/service {service_port} {application.lower()}/pbind cookie insert {persist_cookie_insert}'

    return line

