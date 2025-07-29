
class Virt:
    def __init__(self, virtual_server_id, description='', ip_version='v4', ip_address='0.0.0.0',
                 enabled="ena", services=None, domain_name='', weight=1, priority_for_availability_metric=1,
                 availability_persistence='Disable', nat_address='0.0.0.0', rule_id=None,
                 session_mode='Client IP', invalid_connections='Drop', traffic_contract=1024,
                 wan_link='', return_to_last_hop='Disable'):
        self.virtual_server_id = virtual_server_id
        self.description = description
        self.ip_version = ip_version
        self.ip_address = ip_address
        self.enabled = enabled
        self.services_ids = []
        self.domain_name = domain_name
        self.weight = weight
        self.priority_for_availability_metric = priority_for_availability_metric
        self.availability_persistence = availability_persistence
        self.nat_address = nat_address
        self.rule_id = rule_id
        self.session_mode = session_mode
        self.invalid_connections = invalid_connections
        self.traffic_contract = traffic_contract
        self.wan_link = wan_link
        self.return_to_last_hop = return_to_last_hop

    def get_virtual_server_id(self):
        return self.virtual_server_id

    def set_virtual_server_id(self, value):
        self.virtual_server_id = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def set_ip_version(self, value):
        if value in ['v4', 'v6']:
            self.ip_version = value
        else:
            raise ValueError("Invalid IP version")

    def get_ip_version(self):
        return self.ip_version

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, value):
        self.ip_address = value

    # Example for list manipulation methods for services
    def add_service_id(self, service):
        self.services_ids.append(service)

    def list_all_service_ids(self):
        return [service for service in self.services_ids]

    # def remove_service_id(self, service):
    #     if service in self.services:
    #         self.services.remove(service)
    #     else:
    #         raise ValueError("Service not found")

    # Methods to enable or disable the virtual server

    def get_enabled(self):
        return self.enabled

    def set_enabled(self, value):
        self.enabled = value


    def get_domain_name(self):
        return self.domain_name

    def set_domain_name(self, value):
        self.domain_name = value

    def get_weight(self):
        return self.weight

    def set_weight(self, value):
        if isinstance(value, int) and value > 0:
            self.weight = value
        else:
            raise ValueError("Weight must be a positive integer")

    def get_priority_for_availability_metric(self):
        return self.priority_for_availability_metric

    def set_priority_for_availability_metric(self, value):
        self.priority_for_availability_metric = value

    def get_availability_persistence(self):
        return self.availability_persistence

    def set_availability_persistence(self, value):
        self.availability_persistence = value

    def get_nat_address(self):
        return self.nat_address

    def set_nat_address(self, value):
        self.nat_address = value

    def get_rule_id(self):
        return self.rule_id

    def set_rule_id(self, value):
        self.rule_id = value

    def get_session_mode(self):
        return self.session_mode

    def set_session_mode(self, value):
        if value in ['Client IP', 'Client IP + Client Port']:
            self.session_mode = value
        else:
            raise ValueError("Invalid session mode")

    def get_invalid_connections(self):
        return self.invalid_connections

    def set_invalid_connections(self, value):
        if value in ['Drop', 'Reset']:
            self.invalid_connections = value
        else:
            raise ValueError("Invalid option for invalid connections")

    def get_traffic_contract(self):
        return self.traffic_contract

    def set_traffic_contract(self, value):
        self.traffic_contract = value

    def get_wan_link(self):
        return self.wan_link

    def set_wan_link(self, value):
        self.wan_link = value

    def get_return_to_last_hop(self):
        return self.return_to_last_hop

    def set_return_to_last_hop(self, value):
        if value in ['Enable', 'Disable']:
            self.return_to_last_hop = value
        else:
            raise ValueError("Invalid option for return to last hop")