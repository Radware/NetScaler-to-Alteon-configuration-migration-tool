import ipaddress
from materials import is_fqdn , validate_port, is_app_service_exists, is_protocol_service_exists

class RealServer:

    def __init__(self, name, ip_address=None, comment="", state='ena', ip_version='v4', nat_ip=None, nat_mask=None):
        self.name = name
        self.ip_address = ip_address
        self.state = state
        self.comment = comment
        self.ip_version = ip_version
        self.nat_ip = nat_ip
        self.nat_mask = nat_mask
        self.list_add_ports = []


    def clone(self, new_name):
        return RealServer(new_name)

    def get_list_add_ports(self):
        return self.list_add_ports

    def set_list_add_ports(self, value):
        self.list_add_ports.append(value)

    def get_name(self):
        return self.name

    def set_name(self, value):
        self.name = value

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, value):
        try:
            # Validate IP address format
            ipaddress.ip_address(value)
            self.ip_address = value
        except ValueError as e:
            raise ValueError(f"{value} is not a valid IP address")

    def get_state(self):
        return self.state

    def set_state(self, value):
        self.state = value

    def get_comment(self):
        return self.comment

    def set_comment(self, value):
        self.comment = value

    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    def set_nat_ip(self, value):
        self.nat_ip = value

    def get_nat_ip(self):
        return self.nat_ip

    def set_nat_mask(self, value):
        self.nat_mask = value

    def get_nat_mask(self):
        return self.nat_mask

class Fqdn:
    def __init__(self, fqdn_id, fqdn_domain="", state='ena', ip_version='v4', ttl=None, fqdn_real_template=None, add_port=None):
        self.fqdn_id = fqdn_id
        self.fqdn_domain = fqdn_domain
        self.state = state
        self.ip_version = ip_version
        self.ttl = ttl
        self.fqdn_real_template = fqdn_real_template
        self.add_port = add_port
        self.list_add_ports = []

    def get_add_port(self):
        return self.add_port

    def set_add_port(self, value):
        self.add_port = value

    def clone(self, new_name):
        return Fqdn(new_name)

    def get_fqdn_real_template(self):
        return self.fqdn_real_template

    def set_fqdn_real_template(self):
        self.fqdn_real_template = self.fqdn_real_template

    def get_fqdn_id(self):
        return self.fqdn_id

    def set_fqdn_id(self, value):
        self.fqdn_id = value

    def get_fqdn_domain(self):
        return self.fqdn_domain

    def set_fqdn_domain(self, value):
        try:
            # Validate FQDN format
            if is_fqdn(value):
                self.fqdn_domain = value
            else:
                raise ValueError(f"{value} is not a valid FQDN")
        except ValueError as e:
            raise ValueError(f"{value} is not a valid FQDN")

    def get_state(self):
        return self.state

    def set_state(self, value):
        self.state = value

    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    def get_ttl(self):
        return self.ttl

    def set_ttl(self, value):
        self.ttl = value

    def get_list_add_ports(self):
        return self.list_add_ports

    def set_list_add_ports(self, value):
        self.list_add_ports.append(value)
