import NS_to_ALT
from printer_config import *

FILENAME = input("[+]Please make sure netscaler configuration file is at the same folder as this script, and type here the name including the extention - e.i : netclaser_config.txt   ")


alteon_object, net_scaler = NS_to_ALT.convert(FILENAME)

configuration_file_path = net_scaler.get_alteon_config_file()
unhandled_lines_file_path = net_scaler.get_unhandled_lines_file_path()
unhandled_flags_path = net_scaler.get_unhandled_flags_path()
handled_lines_file_path = net_scaler.get_handled_lines_file_path()

print("[+]Processing Real Server configuration ")
if alteon_object.list_all_real_servers():
    for real_server in alteon_object.list_all_real_servers():
        write_to_alteon_config(configuration_file_path,print_real_server(real_server))
else:
    print("Error - No Real Server configured on Net scaler ? ")

print("[*]Finished Processing Real Server configuration")

print("[+]Processing FQDN configuration")
if alteon_object.list_all_fqdns():
    for fqdn_server in alteon_object.list_all_fqdns():
        write_to_alteon_config(configuration_file_path,print_fqdn_server(fqdn_server))
else:
    print("Note - No FQDN servers found...")
print("[*]Finished Processing FQDN configuration")

print("[+]Processing Group configuration")
if alteon_object.list_all_groups():
    for group in alteon_object.list_all_groups():
        write_to_alteon_config(configuration_file_path,print_group(group))
else:
    print("Error - No Group configured on Net scaler(Might be error with service or serviceGroup) ? ")
print("[*]Finished Processing Group configuration")

print("[+]Processing Health checks monitor configuration")
if alteon_object.list_all_monitors():
    for hc in alteon_object.list_all_monitors():
        write_to_alteon_config(configuration_file_path,print_hc(hc))
else:
    print("Note - No Health Checks Monitor to be converted found...")
print("[*]Finished Processing Health checks monitor configuration")

print("[+]Processing Pre-defined TCP Policy configuration")
write_to_alteon_config(configuration_file_path,pre_define_tcp_pol())
print("[*]Finished Processing Pre-defined TCP Policy configuration")

print("[+]Processing Pre-defined SSL Policy configuration")
write_to_alteon_config(configuration_file_path,pre_define_ssl_pol())
print("[*]Finished Processing Pre-defined SSL Policy configuration")

print("[+]Processing VIRT configuration")
if alteon_object.list_all_virts():
    for virt in alteon_object.list_all_virts():
        write_to_alteon_config(configuration_file_path,print_virt(virt))
else:
    print("Error - No Virts configured on Net scaler(Might be error with VSERVER) ? ")
print("[*]Finished Processing VIRT  configuration")

print("[+]Processing Service configuration")
if alteon_object.list_all_services():
    for service in alteon_object.list_all_services():
        write_to_alteon_config(configuration_file_path,print_service(service))
else:
    print("Error - No Services configured on Net scaler(Might be error with service or serviceGroup) ? ")
print("[*]Finished Processing Service configuration")

uniquify_lines_in_file(net_scaler.get_unhandled_flags_path())
write_to_unhandled_lines(FILENAME,handled_lines_file_path,unhandled_lines_file_path)