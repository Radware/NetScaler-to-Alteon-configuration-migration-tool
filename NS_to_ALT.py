import netscaler
import Alteon
from health_check import *
from virt import Virt
from group import Group
from real_server import *
from service import *
from printer_config import *
from materials import *
import parse_policy


# for each list returned from ns - handle with alteon class:
def get_vserver_dict_by_name(virtName, lst):
    for item in lst:
        if item["virt_name"] == virtName:
            return item


def get_vserver_policy_dict_by_name(virtName, lst):
    for item in lst:
        if item["virt_name"] == virtName:
            return item


def get_serviceGroup_dict_by_name(serviceGroup, lst):
    for item in lst:
        if item["service_name"] == serviceGroup:
            return item


def find_related_https_virt(virtName, lst):
    ip_addr = None
    for item in lst:
        if item["virt_name"] == virtName and item["service_type"].lower() == "http":
            ip_addr = item["virt_ip"]
    if ip_addr:
        for item in lst:
            if item["virt_ip"] == ip_addr and "ssl" in item["service_type"].lower():
                return item["virt_name"]
    else:
        return None


def handle_persistence_type(service_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
    if key == 'persistenceType':
        for feature in add_lb_vserver_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        service_obj.set_persistency_mode(val['alteon_value'])
                        return True  # Success, so we return True
                # If no valid value found in the value_map
                write_to_unhandled_flags(
                    ns_object.get_unhandled_flags_path(),
                    virt_dict["virt_name"],
                    f'Feature : {key} Value: {value}',
                    "Invalid Persistency type to convert"
                )
                return True  # Handled, but with an error
        return False  # Key not found in add_lb_vserver_flags
    return False  # Key is not 'persistenceType', so not handled

def handle_cookie_name(service_obj, key, value):
    if key == 'cookieName':
        service_obj.set_persist_cookie_insert(value)
        return True  # Indicate that the key was handled
    return False  # Indicate that the key was not handled


def handle_lb_method(group_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
    if key == 'lbMethod':
        for feature in add_lb_vserver_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        group_obj.set_slb_metric(val['alteon_value'])
                        return True  # Success, handled
                    else:
                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                 virt_dict["virt_name"],
                                                 f'Feature : {key} Value: {value}',
                                                 "Invalid Load Balancing Method type to convert")
                        return True  # Handled, but with error
    return False  # Not handled


def handle_timeout(service_obj, key, value):
    if key == 'timeout':
        service_obj.set_persistency_timeout(value)
        return True  # Indicate that the key was handled
    return False  # Indicate that the key was not handled

def handle_cltTimeout(service_obj, key, value):
    if key == 'cltTimeout':
        value = int(value)//60
        value = str(value)
        service_obj.set_session_timeout(value)
        return True  # Indicate that the key was handled
    return False  # Indicate that the key was not handled


def handle_netmask(group_obj, key, value):
    if key == 'netmask' or key == 'v6netmasklen':
        group_obj.set_slb_metric('phash')
        group_obj.set_phash_mask(value)
        return True  # Indicate that the key was handled
    return False  # Indicate that the key was not handled


def handle_state(virt_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
    if key == 'state':
        for feature in add_lb_vserver_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        virt_obj.set_enabled(val['alteon_value'])
                        return True  # Success, handled
                    else:
                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                 virt_dict["virt_name"],
                                                 f'Feature : {key} Value: {value}',
                                                 "Unsupported state value, Alteon only supports 'ena' or 'dis'")
                        return True  # Handled, but with error
    return False  # Not handled

def handle_sessionless(service_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
    if key == 'sessionless':
        for feature in add_lb_vserver_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        service_obj.set_not_nat(val['alteon_value'])
                        return True  # Success, handled
                    else:
                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                 virt_dict["virt_name"],
                                                 f'Feature : {key} Value: {value}',
                                                 "Unsupported session config value")
                        return True  # Handled, but with error
    return False  # Not handled


def handle_connfailover(service_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
    if key == "connfailover":
        for feature in add_lb_vserver_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        service_obj.set_mirror(val['alteon_value'])
                        return True  # Success, handled
                    else:
                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                 virt_dict["virt_name"],
                                                 f'Feature : {key} Value: {value}',
                                                 "Unsupported connection failover value")
                        return True  # Handled, but with error
    return False  # Not handled


def handle_comment(virt_obj, key, value):
    if key == 'comment':
        virt_obj.set_description(value)
        return True  # Indicate that the key was handled
    return False  # Indicate that the key was not handled

def handle_service_port(service_obj, key, value):
    if key == 'service_port':
        service_obj.set_service_port(value)
        if value == "53":
            service_obj.set_application("dns")
        elif value == "22":
            service_obj.set_application("ssh")
        elif value == "*":
            service_obj.set_service_port("1")
        elif value == "21":
            service_obj.set_application("ftp")
        return True  # Indicate that the key was handled
    return False  # Indicate that the key was not handled


def handle_virt_ip(virt_obj, virt_dict, key, value, ns_object):
    if key == 'virt_ip':
        if validate_ipv4(value):
            virt_obj.set_ip_version('v4')
            virt_obj.set_ip_address(value)
            return True  # IP was handled, continue
        elif validate_ipv6(value):
            virt_obj.set_ip_version('v6')
            virt_obj.set_ip_address(value)
            return True  # IP was handled, continue
        else:
            write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                     virt_dict["virt_name"],
                                     value,
                                     "Invalid IP address")
            return True  # Handled, but with error
    return False  # IP was not handled


def handle_service_type(service_obj, group_obj, virt_dict, service_mapping_to_ALT, vserver_cert_lst, ns_object):

    if "service_type" in virt_dict:
        value = virt_dict["service_type"]
        for service in service_mapping_to_ALT:
            if service['service'] == value:
                if service['Supported'] == 'True':
                    # Set protocol
                    service_obj.set_protocol(service['protocol'])

                    # Set delayed binding if needed
                    if service['forceproxy'] == 'True':
                        service_obj.set_delayed_binding("forceproxy")

                    # Set application
                    if not service_obj.get_application():
                        service_obj.set_application(service['Application'])

                    # Handle HTTPS specific logic and SSL policy
                    if service_obj.get_delayed_binding() == "forceproxy" and service_obj.get_application().lower() == "https":
                        service_obj.set_ssl_policy_name("default_ssl_pol")

                        # Associate SSL certificate if available
                        for cert in vserver_cert_lst:
                            if virt_dict['virt_name'] == cert['virt_name']:
                                service_obj.set_get_ssl_certificate(cert['certkeyName'])

                        # If no certificate found, adjust settings
                        if service_obj.get_ssl_certificate() == "":
                            service_obj.set_ssl_policy_name("")
                            service_obj.set_delayed_binding("disable")
                            write_to_unhandled_flags(
                                ns_object.get_unhandled_flags_path(),
                                virt_dict["virt_name"],
                                virt_dict['service_type'],
                                "| dbind configuration changed to disable due to lack of binding certificate config"
                            )

                    # Handle "ANY" service type
                    if value == "ANY":
                        service_obj.set_real_server_port("1")
                        group_obj.set_health_check("icmp")
                    return True  # Successfully handled
                else:
                    # Unsupported service type
                    write_to_unhandled_flags(
                        ns_object.get_unhandled_flags_path(),
                        virt_dict["virt_name"],
                        value,
                        "Service Type Not Supported for conversion"
                    )
                    return True  # Handled but unsupported
    return False  # Not handled


def handle_cip(service_obj, virt_dict, service_dict, key, value, service_group_flags, ns_object):
    if key == "cip":
        for feature in service_group_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    # Check if the value is supported in Alteon and if the service type is either SSL or HTTP
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        if "ssl" in virt_dict['service_type'].lower() or "http" in virt_dict['service_type'].lower():
                            service_obj.set_insert_xff(val['alteon_value'])
                            return True  # Handled successfully
                    else:
                        # Log error for unsupported XFF setting for non-HTTP services
                        write_to_unhandled_flags(
                            ns_object.get_unhandled_flags_path(),
                            f'Vserver: {virt_dict["virt_name"]} Service: {service_dict["service_name"]}',
                            f'Unsupported feature: {key} | value: {value} |',
                            "Unsupported XFF Setting Service that are not HTTP"
                        )
                        return True  # Handled but with error
    return False  # Not handled


def handle_usip(service_obj, virt_dict, service_dict, key, value, service_group_flags, ns_object):
    if key == "usip":
        for feature in service_group_flags:
            if feature['netscaler_vserver_feature'] == key:
                for val in feature['value_map']:
                    # Check if the value is supported in Alteon
                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                        service_obj.set_pip(val['alteon_value'])
                        continue  # Continue to check other flags for usip
                    else:
                        # Log error for unsupported NAT type
                        write_to_unhandled_flags(
                            ns_object.get_unhandled_flags_path(),
                            f'Vserver: {virt_dict["virt_name"]} Service: {service_dict["service_name"]}',
                            f'Unsupported feature: {key} | value: {value} |',
                            "Unsupported NAT Type"
                        )
                        continue  # Continue checking other flags even after logging the error
        return True  # All flags for usip processed
    return False  # Not handled


def handle_cka(service_obj, key, value):
    if key == 'CKA':
        if value == 'YES':
            service_obj.set_TCPFrontend("keep_alive_tcp_pol")
            return True  # Indicate that the key was handled successfully
    return False  # Indicate that the key was not handled


def initialize_objects(virt_dict, service_dict):
    # Initialize the VIRT object with the IP address and name from virt_dict
    virt_obj = Virt(virt_dict["virt_name"])

    # Ensure that the IP address is set for the VIRT object
    if 'virt_ip' in virt_dict:
        virt_obj.set_ip_address(virt_dict["virt_ip"])

    # Initialize the Service and Group objects
    service_obj = Service(service_dict["service_name"])
    group_obj = Group(f"grp_{service_dict['service_name']}")

    return virt_obj, service_obj, group_obj


def associate_service_with_virt_group(service_obj, virt_obj, service_dict, group_obj):
    # Associate the service with virt and group
    virt_obj.add_service_id(service_dict["service_name"])
    service_obj.set_virt_assoiciate(virt_obj)
    service_obj.set_group_id(group_obj.get_group_id())


def handle_service_group_ports(service_obj, group_obj, service_dict, bind_service_group_no_mon, alt_objc):
    service_ports_lst = []

    # Process the services bound to the group or VIRT
    for service_grp in bind_service_group_no_mon:
        if service_dict['service_name'] == service_grp['service_name']:
            service_ports_lst.append(service_grp['port'])

            # Handle multiple unique service ports
            if len(set(service_ports_lst)) > 1:
                for port in get_unique_values(service_ports_lst):
                    alt_objc.duplicate_real_server(service_grp['service_member'],
                                                   f"{service_grp['service_member']}_{port}", port)
                    group_obj.add_real_server(
                        {'service_member': f"{service_grp['service_member']}_{port}", 'port': service_grp['port']})
                service_obj.set_real_server_port("0")

            # Handle a single service port
            elif len(set(service_ports_lst)) == 1:
                group_obj.add_real_server({'service_member': service_grp['service_member'], 'port': ''})
                service_obj.set_real_server_port(service_grp['port'])

    # Add the VIRT and Group to alt_objc to ensure they are correctly associated
    alt_objc.add_group(group_obj)
    alt_objc.add_virt(service_obj.get_virt_assoiciate())


def is_redirect_policy(virt_with_pol, add_responder_policy_lst, add_responder_action_lst):
    return parse_policy.is_redirect_http_https_policy(virt_with_pol["policyName"],
                                                      add_responder_policy_lst,
                                                      add_responder_action_lst)


def handle_https_redirect(virt_dict, virt_with_pol, add_lb_vserver_lst, alt_objc):
    if virt_dict["service_type"] == "HTTP":
        https_virt_name = find_related_https_virt(virt_dict['virt_name'], add_lb_vserver_lst)
        if https_virt_name:
            # Initialize the Service object for redirection
            service_obj = Service(
                service_id=f"SVC_{virt_dict['virt_name']}",
                action='redirect',
                redirect_string='"https://$host/$path?$query"',
                service_port=virt_dict['service_port'],
                application=virt_dict['service_type'],
                virt_assoiciate=https_virt_name,
                protocol="TCP"
            )
            # Add the service object to alt_objc
            alt_objc.add_service(service_obj)
            return True  # Indicate success
    return False  # Indicate no redirect
#     self.bind_ssl_vserver_list
#     self.add_responder_policy_list
#     self.add_responder_action_list
#     self.bind_lb_vserver_no_policy_list
#     self.add_lb_vserver_virt_list
#     self.add_serviceGroup_list
#     self.bind_serviceGroup_no_monitor_list

def assemble_slb(bind_lb_vserver_lst,
                 add_lb_vserver_lst,
                 add_serviceGroup_lst,
                 add_service_lst,  # Added this parameter
                 bind_lb_vserver_lst_with_pol_lst,
                 add_responder_policy_lst,
                 add_responder_action_lst,
                 bind_service_group_no_mon,
                 vserver_cert_lst,
                 ns_object,
                 alt_objc):
    # Combine service groups and individual services into a unified list
    unified_service_lst = [{"type": "group", **sg} for sg in add_serviceGroup_lst] + \
                          [{"type": "service", **svc} for svc in add_service_lst]

    # Track VIRTs, services, and groups by (name, IP) combination to avoid duplication
    virt_dict_by_name_ip = {}

    # Process bind_lb_vserver_lst
    for bind_dict in bind_lb_vserver_lst:
        virt_dict = get_vserver_dict_by_name(bind_dict["virt_name"], add_lb_vserver_lst)

        # Ensure virt_dict has a valid IP address
        if 'virt_ip' not in virt_dict or virt_dict['virt_ip'] == '0.0.0.0':
            write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                     virt_dict["virt_name"],
                                     virt_dict['virt_ip'],
                                     "Unsupported for Empty or invalid IP address")
            continue

        # Get the service dict from the unified list (service group or service)
        service_dict = get_serviceGroup_dict_by_name(bind_dict["service_name"], unified_service_lst)
        virt_with_pol = get_vserver_policy_dict_by_name(bind_dict["virt_name"], bind_lb_vserver_lst_with_pol_lst)

        # Handle redirection policies if both service_dict and virt_with_pol exist
        if service_dict and virt_with_pol:
            if is_redirect_policy(virt_with_pol, add_responder_policy_lst, add_responder_action_lst):
                if handle_https_redirect(virt_dict, virt_with_pol, add_lb_vserver_lst, alt_objc):
                    continue

        if virt_dict and service_dict:
            virt_name = virt_dict["virt_name"]
            virt_ip = virt_dict["virt_ip"]

            # Key for identifying a unique VIRT based on name and IP
            virt_key = (virt_name, virt_ip)

            # Check if the VIRT already exists by its name and IP combination
            if virt_key not in virt_dict_by_name_ip:
                # Initialize objects for VIRT, Service, and Group (only if VIRT doesn't already exist)
                virt_obj, service_obj, group_obj = initialize_objects(virt_dict, service_dict)

                # Store the VIRT, service, and group for future reuse
                virt_dict_by_name_ip[virt_key] = {
                    "virt_obj": virt_obj,
                    "service_obj": service_obj,
                    "group_obj": group_obj
                }
            else:
                # If VIRT already exists, reuse the existing service and group
                virt_obj = virt_dict_by_name_ip[virt_key]["virt_obj"]
                service_obj = virt_dict_by_name_ip[virt_key]["service_obj"]
                group_obj = virt_dict_by_name_ip[virt_key]["group_obj"]

            # Associate the service with the VIRT and group (ensure only one association)
            associate_service_with_virt_group(service_obj, virt_obj, service_dict, group_obj)

            # Handle service group ports and real server duplication
            handle_service_group_ports(service_obj, group_obj, service_dict, bind_service_group_no_mon, alt_objc)

            # Process virt_dict for various keys
            for key, value in virt_dict.items():
                if key == "virt_name":
                    continue
                handled = False
                # Call each handler independently
                if handle_service_type(service_obj, group_obj, virt_dict, service_mapping_to_ALT, vserver_cert_lst,
                                       ns_object):
                    handled = True
                if handle_service_port(service_obj, key, value):
                    handled = True
                if supported_attr_vserver(key):
                    if handle_persistence_type(service_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
                        handled = True
                    if handle_cookie_name(service_obj, key, value):
                        handled = True
                    if handle_lb_method(group_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
                        handled = True
                    if handle_timeout(service_obj, key, value):
                        handled = True
                    if handle_cltTimeout(service_obj, key, value):
                        handled = True
                    if handle_netmask(group_obj, key, value):
                        handled = True
                    if handle_state(virt_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
                        handled = True
                    if handle_sessionless(service_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
                        handled = True
                    if handle_connfailover(service_obj, virt_dict, key, value, add_lb_vserver_flags, ns_object):
                        handled = True
                    if handle_comment(virt_obj, key, value):
                        handled = True

                if not handled:
                    # Log unhandled keys
                    write_to_unhandled_flags(
                        ns_object.get_unhandled_flags_path(),
                        virt_dict["virt_name"],
                        f'Unsupported feature: {key} | value: {value} |',
                        "Virt exception: This feature is not included in the converter tool yet"
                    )

            # Process service_dict for various keys
            for key, value in service_dict.items():
                if key == 'port':
                    service_obj.set_service_port(value)
                    continue
                if supported_attr_service(key):
                    if handle_cip(service_obj, virt_dict, service_dict, key, value, service_group_flags, ns_object):
                        continue
                    if handle_usip(service_obj, virt_dict, service_dict, key, value, service_group_flags, ns_object):
                        continue
                    if handle_cka(service_obj, key, value):
                        continue
                    if key == "comment":
                        service_obj.set_description(value)
                        continue
                    if key == "service_type":
                        continue
                    if key == "service_name":
                        continue
                else:
                    write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                             f'Vserver: {virt_dict["virt_name"]} Service: {service_dict["service_name"]}',
                                             f'Unsupported feature: {key} | value: {value} |',
                                             "Service exception: This feature is not included in the converter tool yet")
                    continue

            # Add the virt_obj, service, and group only if they were not already added
            if virt_key not in alt_objc.list_all_virts():
                alt_objc.add_service(service_obj)
                alt_objc.add_group(group_obj)
                alt_objc.add_virt(virt_obj)


        else:
            write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                     f'Vserver: {virt_dict["virt_name"]} Service: {service_dict["service_name"]}',
                                     f'Issue with creating VIRT and Service for the above',
                                     "")


#     self.add_server_list
def add_server_to_real_server(list_of_dict,ns_obj ,alteon_obj):
    for add_server_dict in list_of_dict:
        real_server_alt = RealServer(add_server_dict["server_name"])
        if validate_ipv6(add_server_dict["ip_address"]):
            real_server_alt.set_ip_version("v6")
        if validate_ipv4(add_server_dict["ip_address"]):
            real_server_alt.set_ip_version("v4")
        if "state" in add_server_dict:
            if add_server_dict["state"] == "DISABLED":
                real_server_alt.set_state("dis")
        if "ip_address" in add_server_dict:
            real_server_alt.set_ip_address(add_server_dict["ip_address"])
        if "translationIp" in add_server_dict:
            real_server_alt.set_nat_ip(add_server_dict["translationIp"])
        if "translationMask" in add_server_dict:
            real_server_alt.set_nat_mask(add_server_dict["translationMask"])
        if "comment" in add_server_dict:
            real_server_alt.set_nat_mask(add_server_dict["comment"])
        for feature in add_server_real_server_map:
            if feature["ns_feature_name"] in add_server_dict and feature["supported_alt"] == False:
                write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                         f'Server: {add_server_dict["server_name"]} Feature: {feature["ns_feature_name"]}',
                                         f'Feature is unsupported on converter tool',
                                         "")
        alteon_obj.add_real_server(real_server_alt)


#     self.add_server_fqdn_list
def add_server_to_alt_fqdn(list_of_dict, alteon_obj,ns_obj):
    for fqdn_dict in list_of_dict:
        fqdn_alt = Fqdn(fqdn_dict['server_name'],fqdn_dict['fqdn'])
        if 'domainResolveRetry' in fqdn_dict:
            fqdn_alt.set_ttl(fqdn_dict['domainResolveRetry'])
        if 'state' in fqdn_dict:
            if fqdn_dict["state"] == "DISABLED":
                fqdn_alt.set_state("dis")
        if 'queryType' in fqdn_dict:
            if fqdn_dict["queryType"] == 'AAAA':
                fqdn_alt.set_ip_version("v6")
        for feature in add_server_real_server_map:
            if feature["ns_feature_name"] in fqdn_dict and feature["supported_alt"] == False:
                write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                         f'Server: {fqdn_dict["server_name"]} Feature: {feature["ns_feature_name"]}',
                                         f'Server Feature is unsupported on converter tool',
                                         "")
                pass
        alteon_obj.add_fqdn(fqdn_alt)


#     self.monitor_list |  will support: TCP /UDP /ICMP / HTTP(S)/ARP
def add_monitor_to_alt(monitor_list, alteon_obj, ns_obj):
    for monitor in monitor_list:
        if supported_monitors(monitor['type']):
            if "http" in monitor['type'].lower():
                http_mon = HTTPMonitor(name=monitor['monitorName'])
                http_mon.set_http_id(monitor['monitorName'])
                for key, value in monitor.items():
                    if key == 'respCode':
                        http_mon.set_expected_return_codes(value)
                    if key == 'recv':
                        http_mon.set_expected_return_string(value)
                    if key == 'httpRequest':
                        request_splitted = value.split(" ")
                        http_mon.set_method(request_splitted[0])
                        http_mon.set_path(request_splitted[1])
                    if key == 'send':
                        if r'\r\n' not in value:
                            request_splitted = value.split(" ")
                            http_mon.set_method(request_splitted[0])
                            http_mon.set_path(request_splitted[1])
                        if r'\r\n' in value:
                            request_splitted = value.split(r'\r\n')
                            http_mon.set_path(request_splitted[0])
                            http_mon.set_path(request_splitted[1].split(r'\r\n\r\n')[0])
                            http_mon.set_body(value.split(r'\r\n\r\n')[1])
                    if key == 'interval':
                        http_mon.set_interval(value)
                    if key == 'resptimeout':
                        http_mon.set_response_timeout(value)
                    if key == 'destPort':
                        http_mon.set_destination_port(value)
                    if key == 'destIP':
                        http_mon.set_destination_ip(value)
                    if key == 'reverse':
                        invert_val = 'disabled'
                        if value.lower() == 'yes':
                            invert_val = 'enabled'
                        http_mon.set_invert_result(invert_val)
                    if key == 'secure':
                        secure_val = 'disabled'
                        if value.lower() == 'yes':
                            secure_val = 'enabled'
                        http_mon.set_https(secure_val)
                    if key == 'downTime':
                        http_mon.set_checks_interval_on_downtime(value)
                    if key == 'retries':
                        http_mon.set_retries_to_failure(value)
                    if key == 'customHeaders':
                        http_mon.set_header(value)
                    else:
                        write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                                 f'Monitor: {monitor["monitorName"]} Feature: {key} , Value: {value}',
                                                 f'Monitor Feature is unsupported on converter tool',
                                                 "")
                alteon_obj.add_monitor(http_mon)

            if "tcp" in monitor['type'].lower():
                tcp_mon = TCPMonitor(tcp_id=monitor['monitorName'])
                for key, value in monitor.items():
                    if key == 'interval':
                        tcp_mon.set_interval(value)
                    if key == 'resptimeout':
                        tcp_mon.set_response_timeout(value)
                    if key == 'destPort':
                        tcp_mon.set_destination_port(value)
                    if key == 'reverse':
                        invert_val = 'disabled'
                        if value.lower() == 'yes':
                            invert_val = 'enabled'
                        tcp_mon.set_invert_result(invert_val)
                    if key == 'downTime':
                        tcp_mon.set_checks_interval_on_downtime(value)
                    if key == 'retries':
                        tcp_mon.set_retries_to_failure(value)
                    if key == 'failureRetries':
                        tcp_mon.set_retries_to_failure(value)
                    if key == 'successRetries':
                        tcp_mon.set_retries_to_restore(value)
                    else:
                        write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                                 f'Monitor: {monitor["monitorName"]} Feature: {key} , Value: {value}',
                                                 f'Monitor Feature is unsupported on converter tool',
                                                 "")
                alteon_obj.add_monitor(tcp_mon)

            if "udp" in monitor['type'].lower():
                udp_mon = UDPMonitor(name=monitor['monitorName'])
                udp_mon.set_udp_id(monitor['monitorName'])
                for key, value in monitor.items():
                    if key == 'interval':
                        udp_mon.set_interval(value)
                    if key == 'resptimeout':
                        udp_mon.set_response_timeout(value)
                    if key == 'destPort':
                        udp_mon.set_destination_port(value)
                    if key == 'failureRetries':
                        udp_mon.set_retries_to_failure(value)
                    if key == 'successRetries':
                        udp_mon.set_retries_to_restore(value)
                    if key == 'reverse':
                        invert_val = 'disabled'
                        if value.lower() == 'yes':
                            invert_val = 'enabled'
                        udp_mon.set_invert_result(invert_val)
                    if key == 'downTime':
                        udp_mon.set_checks_interval_on_downtime(value)
                    if key == 'retries':
                        udp_mon.set_retries_to_failure(value)
                    if key == 'destIP':
                        udp_mon.set_destination_ip(value)
                    else:
                        write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                                 f'Monitor: {monitor["monitorName"]} Feature: {key} , Value: {value}',
                                                 f'Monitor Feature is unsupported on converter tool',
                                                 "")
                alteon_obj.add_monitor(udp_mon)

            if "icmp" in monitor['type'].lower():
                icmp_mon = ICMPMonitor(name=monitor['monitorName'])
                icmp_mon.set_icmp_id(monitor['monitorName'])
                for key, value in monitor.items():
                    if key == 'interval':
                        icmp_mon.set_interval(value)
                    if key == 'resptimeout':
                        icmp_mon.set_response_timeout(value)
                    if key == 'reverse':
                        invert_val = 'disabled'
                        if value.lower() == 'yes':
                            invert_val = 'enabled'
                        icmp_mon.set_invert_result(invert_val)
                    if key == 'downTime':
                        icmp_mon.set_checks_interval_on_downtime(value)
                    if key == 'failureRetries':
                        icmp_mon.set_retries_to_failure(value)
                    if key == 'successRetries':
                        icmp_mon.set_retries_to_restore(value)
                    if key == 'destIP':
                        icmp_mon.set_destination_ip(value)
                    else:
                        write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                                 f'Monitor: {monitor["monitorName"]} Feature: {key} , Value: {value}',
                                                 f'Monitor Feature is unsupported on converter tool',
                                                 "")
                    alteon_obj.add_monitor(icmp_mon)

            if "arp" in monitor['type'].lower():
                arp_mon = ARPMonitor(name=monitor['monitorName'])
                if monitor['monitorName'].lower() == "arp":
                    arp_mon.set_name("arp_1")
                for key, value in monitor.items():
                    if key == 'interval':
                        arp_mon.set_interval(value)
                    if key == 'resptimeout':
                        arp_mon.set_response_timeout(value)
                    if key == 'reverse':
                        invert_val = 'disabled'
                        if value.lower() == 'yes':
                            invert_val = 'enabled'
                        arp_mon.set_invert_result(invert_val)
                    if key == 'downTime':
                        arp_mon.set_check_interval_downtime(value)
                    if key == 'failureRetries':
                        arp_mon.set_retries_to_failure(value)
                    if key == 'successRetries':
                        arp_mon.set_retries_to_restore(value)
                    if key == 'destIP':
                        arp_mon.set_destination_ip(value)
                    else:
                        write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                                 f'Monitor: {monitor["monitorName"]} Feature: {key} , Value: {value}',
                                                 f'Monitor Feature is unsupported on converter tool',
                                                 "")
                        pass
                    alteon_obj.add_monitor(arp_mon)
        else:
            write_to_unhandled_flags(ns_obj.get_unhandled_flags_path(),
                                     f'Monitor: {monitor["monitorName"]} Type: {monitor["type"]}',
                                     f'Monitor Type is unsupported on converter tool',
                                     "")
            pass







# starting new project:
def convert(file_path):
    """This Method start converter operation by feeding this Method file path of the Net Scaler configuration"""
    file_names = create_conversion_project(file_path)
    ns_obj = netscaler.Netscaler(file_path,unhandled_lines_file_path=file_names['unhandled_lines'],
                                 unhandled_flags_path=file_names['unhandled_flags'],
                                 handled_lines_file_path=file_names['handled_lines'],
                                 alteon_config_file=file_names['alteon_config_file'])

    # Parse Alteon Config file to be returned in dict to cast into Alteon object
    ns_obj.slb_config_extract(ns_obj.read_file())

    # Create Alteon Object
    alteon_obj = Alteon.Alteon()
    #print(ns_obj.get_add_server_list())
    add_server_to_real_server(ns_obj.get_add_server_list(),ns_obj,alteon_obj )
    #print(ns_obj.get_add_server_fqdn_list())
    add_monitor_to_alt(ns_obj.get_monitor_list(), alteon_obj, ns_obj)

    add_server_to_alt_fqdn(ns_obj.get_add_server_fqdn_list(),alteon_obj,ns_obj )
    assemble_slb(ns_obj.get_bind_lb_vserver_no_policy_list(),
                 ns_obj.get_add_lb_vserver_virt_list(),
                 ns_obj.get_add_serviceGroup_list(),
                 ns_obj.get_add_service_list(),
                 ns_obj.get_bind_lb_vserver_with_policy_list(),
                 ns_obj.get_add_responder_policy_list(),
                 ns_obj.get_add_responder_action_list(),
                 ns_obj.get_bind_serviceGroup_no_monitor_list(),
                 ns_obj.get_bind_ssl_vserver_list(),
                 ns_obj,
                 alteon_obj)

    return alteon_obj, ns_obj

#Unhandaled dicts (to be supported next vestion):
#     self.link_ssl_certKey_list
#     self.bind_ssl_profile_vserver_list
#     self.add_ssl_profile_list
#     self.bind_lb_vserver_with_policy_list



