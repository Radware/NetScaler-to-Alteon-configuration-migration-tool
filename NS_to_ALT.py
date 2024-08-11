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
                 bind_lb_vserver_lst_with_pol_lst,
                 add_responder_policy_lst,
                 add_responder_action_lst,
                 bind_service_group_no_mon,
                 vserver_cert_lst,
                 ns_object,
                 alt_objc):

    for dict in bind_lb_vserver_lst:
        virt_dict = get_vserver_dict_by_name(dict["virt_name"],
                                             add_lb_vserver_lst)
        # Check if the IP address is '0.0.0.0' or there is no IP address
        if 'virt_ip' not in virt_dict or virt_dict['virt_ip'] == '0.0.0.0':
            write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                     virt_dict["virt_name"],
                                     virt_dict['virt_ip'] ,
                                     "Unsupported for Empty or invalid IP address")
            continue
        service_dict = get_serviceGroup_dict_by_name(dict["service_name"],
                                                     add_serviceGroup_lst)
        virt_with_pol = get_vserver_policy_dict_by_name(dict["virt_name"],
                                                        bind_lb_vserver_lst_with_pol_lst)

        if service_dict and virt_with_pol:
            if parse_policy.is_redirect_http_https_policy(virt_with_pol["policyName"],
                                                       add_responder_policy_lst,
                                                       add_responder_action_lst):
                if virt_dict["service_type"] == "HTTP":
                    https_virt_name = find_related_https_virt(virt_dict['virt_name'], add_lb_vserver_lst)
                    if https_virt_name:
                        service_obj = Service(service_id=f"SVC_{virt_dict['virt_name']}",
                                              action='redirect',
                                              redirect_string= '"https://$host/$path?$query"',
                                              service_port=virt_dict['service_port'],
                                              application= virt_dict['service_type'],
                                              virt_assoiciate=https_virt_name,
                                              protocol="TCP"
                                             )
                        alt_objc.add_service(service_obj)
                        continue
                    else:
                        pass

        if virt_dict and service_dict :
            #flag_is_service_exists= False
            virt_obj = Virt(virt_dict["virt_name"])
            # if alt_objc.get_service(service_dict["service_name"]):
            #     service_obj = alt_objc.get_service(service_dict["service_name"])
            #     flag_is_service_exists = True
            # else:
            service_obj = Service(service_dict["service_name"])
            virt_obj.add_service_id(service_dict["service_name"])

            service_obj.set_virt_assoiciate(virt_dict["virt_name"])
            group_obj = Group(f"grp_{service_dict['service_name']}")
            service_obj.set_group_id(group_obj.get_group_id())
            service_ports_lst = []
            for service_grp in bind_service_group_no_mon:
                if service_dict['service_name'] == service_grp['service_name']:

                    service_ports_lst.append(service_grp['port'])
                    if len(set(service_ports_lst)) > 1:
                        for port in get_unique_values(service_ports_lst):
                            alt_objc.duplicate_real_server(service_grp['service_member'],f"{service_grp['service_member']}_{port}",port)
                            group_obj.add_real_server(
                                {'service_member': f"{service_grp['service_member']}_{port}", 'port': service_grp['port']})
                        service_obj.set_real_server_port("0")
            for service_grp in bind_service_group_no_mon:
                if service_dict['service_name'] == service_grp['service_name']:
                    if len(set(service_ports_lst)) == 1:
                        group_obj.add_real_server({'service_member': service_grp['service_member'], 'port': ''})
                        service_obj.set_real_server_port(service_grp['port'])

            for key, value in virt_dict.items():
                if key == "virt_name":
                    continue
                if key == "service_type":
                    for service in service_mapping_to_ALT:
                        if service['service'] == value:
                            if service['Supported'] == 'True':
                                service_obj.set_protocol(service['protocol'])
                                if service['forceproxy'] == 'True':
                                    service_obj.set_delayed_binding("forceproxy")
                                service_obj.set_application(service['Application'])
                                if service_obj.get_delayed_binding() == "forceproxy" and service_obj.get_application().lower() == "https":
                                    service_obj.set_ssl_policy_name("default_ssl_pol")
                                    for cert in vserver_cert_lst:
                                        if virt_dict['virt_name'] == cert['virt_name']:
                                            service_obj.set_get_ssl_certificate(cert['certkeyName'])
                                if service_obj.get_ssl_certificate() == "":
                                    service_obj.set_ssl_policy_name("")
                                    service_obj.set_delayed_binding("disable")
                                    write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                             virt_dict["virt_name"],
                                                             virt_dict['service_type'],
                                                             "| dbind configuration changed to disable due to lake of binding certificate config ")
                                if value == "ANY":
                                    service_obj.set_real_server_port("1")
                                    group_obj.set_health_check("icmp")


                                continue
                            else:
                                write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                         virt_dict["virt_name"],
                                                         virt_dict['service_type'],
                                                         "| Service Type Not Supported for convert")
                                continue

                if key == 'virt_ip':
                    if validate_ipv4(value):
                        virt_obj.set_ip_version('v4')
                        virt_obj.set_ip_address(value)
                        continue
                    if validate_ipv6(value):
                        virt_obj.set_ip_version('v6')
                        virt_obj.set_ip_address(value)
                        continue
                    else:
                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                 virt_dict["virt_name"],
                                                 value,
                                                 "Invalid Ip address")
                if key == 'service_port':
                    service_obj.set_service_port(value)
                    if value == "53":
                        service_obj.set_application("dns")
                    if value == "22":
                        service_obj.set_application("ssh")
                    if value == "*":
                        service_obj.set_service_port("1")
                    if value == "21":
                        service_obj.set_application("ftp")
                    continue

                if supported_attr_vserver(key):
                    if key == 'persistenceType':
                        for feature in add_lb_vserver_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        service_obj.set_persistency_mode(val['alteon_value'])
                                        continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 virt_dict["virt_name"],
                                                                 f'Feature : {key} Value: {value}',
                                                                 "Invalid Persistency type to convert")
                                        continue
                    if key == 'cookieName':
                        service_obj.set_persist_cookie_insert(value)
                        continue

                    if key == 'lbMethod':
                        for feature in add_lb_vserver_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        group_obj.set_slb_metric(val['alteon_value'])
                                        continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 virt_dict["virt_name"],
                                                                 f'Feature : {key} Value: {value}',
                                                                 "Invalid Load Balancing Method type to convert")
                                        continue
                    if key == 'timeout':
                        service_obj.set_persistency_timeout(value)
                        continue
                    if key == 'netmask' or key == 'v6netmasklen':
                        group_obj.set_slb_metric('phash')
                        group_obj.set_phash_mask(value)
                        continue
                    if key == 'state':
                        for feature in add_lb_vserver_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        virt_obj.set_enabled(val['alteon_value'])
                                        continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 virt_dict["virt_name"],
                                                                 f'Feature : {key} Value: {value}',
                                                                 "Unsupported state value alteon gets ena or dis")
                                        continue
                    if key == 'sessionless':
                        for feature in add_lb_vserver_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        service_obj.set_not_nat(val['alteon_value'])
                                        continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 virt_dict["virt_name"],
                                                                 f'Feature : {key} Value: {value}',
                                                                 "Unsupported session config value")
                                        continue
                    if key == "connfailover":
                        for feature in add_lb_vserver_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        service_obj.set_mirror(val['alteon_value'])
                                        continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 virt_dict["virt_name"],
                                                                 f'Feature : {key} Value: {value}',
                                                                 "Unsupported connection failover value")
                                        continue

                    if key == 'comment':
                        virt_obj.set_description(value)
                        continue


                else:
                    write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                             virt_dict["virt_name"],
                                             f'Unsupported  feature: {key} | value: {value} |',
                                             "Virt exception: This Feature Not included on the converter tool yet")
                    continue

            for key, value in service_dict.items():
                if key == 'port':
                    service_obj.set_service_port(value)
                    continue

                if supported_attr_service(key):
                    if key == "cip":
                        for feature in service_group_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        if "ssl" in virt_dict['service_type'].lower() or "http" in virt_dict['service_type'].lower():
                                            service_obj.set_insert_xff(val['alteon_value'])
                                            continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 f'Vserver: {virt_dict["virt_name"]} Service: {service_dict["service_name"]}',
                                                                 f'Unsupported  feature: {key} | value: {value} |',
                                                                 "Unsupported XFF Setting Service that are not HTTP")
                                        continue

                    if key == "usip" :
                        for feature in service_group_flags:
                            if feature['netscaler_vserver_feature'] == key:
                                for val in feature['value_map']:
                                    if value == val['netscaler_value'] and val['alteon_support'] is True:
                                        service_obj.set_pip(val['alteon_value'])
                                        continue
                                    else:
                                        write_to_unhandled_flags(ns_object.get_unhandled_flags_path(),
                                                                 f'Vserver: {virt_dict["virt_name"]} Service: {service_dict["service_name"]}',
                                                                 f'Unsupported  feature: {key} | value: {value} |',
                                                                 "Unsupported NAT Type")
                                        continue
                    if key == 'CKA':
                        if value == 'YES':
                            service_obj.set_TCPFrontend("keep_alive_tcp_pol")
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
                                             f'Unsupported  feature: {key} | value: {value} |',
                                             f"Service exception: This Feature Not included on the converter tool yet")
                    continue

            #if not flag_is_service_exists:
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



