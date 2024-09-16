import ipaddress
from materials import is_fqdn , validate_port, is_app_service_exists, is_protocol_service_exists
import logging
from health_check import *
from virt import Virt
from group import Group
from real_server import *
from service import Service


# Logger configuration
logger = logging.getLogger('Alteon')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('alteon.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class Alteon:
    def __init__(self):
        self.virts = []
        self.services = []
        self.groups = []
        self.real_servers = []
        self.fqdn_list = []
        self.monitors = []
        self.ssl_policies = []

    # Real Server methods
    def add_real_server(self, real_server):
        self.real_servers.append(real_server)

    def remove_real_server(self, name):
        self.real_servers = [server for server in self.real_servers if server.name != name]

    def get_real_server(self, name):
        for server in self.real_servers:
            if server.name == name:
                return server
        return None

    def list_all_real_servers(self):
        if self.real_servers:
            return self.real_servers
        return None

    def duplicate_real_server(self, existing_name, new_name, new_addport):
        if self.get_real_server(existing_name):
            original_server = self.get_real_server(existing_name)
        else:
            original_server = self.get_fqdn(existing_name)
        if original_server:
            new_server = original_server.clone(new_name)
            new_server.set_list_add_ports(new_addport)
            new_server.set_ip_address(original_server.get_ip_address())
            self.add_real_server(new_server)
            return new_server
        else:
            raise ValueError(f"Real server with name {existing_name} does not exist")

    def add_fqdn(self, fqdn):
        self.fqdn_list.append(fqdn)

    def remove_fqdn(self, fqdn_id):
        self.fqdn_list = [fqdn for fqdn in self.fqdn_list if fqdn.fqdn_id != fqdn_id]

    def get_fqdn(self, fqdn_id):
        for fqdn in self.fqdn_list:
            if fqdn.fqdn_id == fqdn_id:
                return fqdn
        return None

    def list_all_fqdns(self):
        if self.fqdn_list:
            return self.fqdn_list
        return None

        # Group methods

    def add_group(self, new_group):
        for group in self.groups:
            if group.get_group_id() == new_group.get_group_id():
                logger.info(f"Group with ID {new_group.get_group_id()} already exists. Skipping addition.")
                return
        self.groups.append(new_group)
        logger.info(f"Group with ID {new_group.get_group_id()} added successfully.")

    def remove_group(self, name):
        self.groups = [group for group in self.groups if group.get_group_id() != name]

    def get_group(self, group_id):
        for group in self.groups:
            if group.get_group_id() == group_id:
                return group
        return None

    def list_all_groups(self):
        return self.groups if self.groups else None

    # Service methods
    def add_service(self, service):
        existing_service = self.get_service(service.service_id)
        if existing_service:
            logger.info(f"Service with ID {service.service_id} already exists. Skipping addition.")
            return
        # If not, add the new service
        logger.info(f"Service with ID {service.service_id} added successfully.")
        self.services.append(service)

    def remove_service(self, name):
        self.services = [service for service in self.services if service.name != name]

    def get_service(self, service_id):
        for service in self.services:
            if service.service_id == service_id:
                return service
        return None

    def list_all_services(self):
        return self.services if self.services else None

    # Virtual Server (Virt) methods
    def add_virt(self, virt):
        # Check if an object with the same virtual_server_id and ip_address already exists
        for existing_virt in self.virts:
            if existing_virt.virtual_server_id == virt.virtual_server_id and existing_virt.ip_address == virt.ip_address:
                return

        # If no match is found, add the new object
        self.virts.append(virt)
    def remove_virt(self, name):
        self.virts = [virt for virt in self.virts if virt.name != name]

    def get_virt(self, name):
        for virt in self.virts:
            if virt.virtual_server_id == name:
                return virt
        return None

    def list_all_virts(self):
        return self.virts if self.virts else None

    def get_added_virt_names(self):
        return [virt.virtual_server_id for virt in self.virts]

    # Monitor methods
    def add_monitor(self, monitor):
        self.monitors.append(monitor)

    def remove_monitor(self, name):
        self.monitors = [monitor for monitor in self.monitors if monitor.name != name]

    def get_monitor(self, name):
        for monitor in self.monitors:
            if monitor.name == name:
                return monitor
        return None

    def list_all_monitors(self):
        return self.monitors if self.monitors else None

        # SSL Policy methods

    def add_ssl_policy(self, ssl_policy):
        self.ssl_policies.append(ssl_policy)

    def remove_ssl_policy(self, policy_id):
        self.ssl_policies = [policy for policy in self.ssl_policies if policy.policy_id != policy_id]

    def get_ssl_policy(self, policy_id):
        for policy in self.ssl_policies:
            if policy.policy_id == policy_id:
                return policy
        return None

    def list_all_ssl_policies(self):
        return self.ssl_policies if self.ssl_policies else None

    def list_all_attributes(self):
        """Prints all the attributes of the Alteon instance."""
        attributes = {
            'Virtual Servers': self.virts,
            'Services': self.services,
            'Groups': self.groups,
            'Real Servers': self.real_servers,
            'FQDNs': self.fqdn_list,
            'Monitors': self.monitors,
            'SSL Policies': self.ssl_policies
        }
        for attr, value in attributes.items():
            print(f"{attr}: {value}")





