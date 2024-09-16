from real_server import RealServer


class Group:
    def __init__(self, group_id, description=" ", group_type="Local", ip_version="IPv4", slb_metric="leastconns",
                 health_check="tcp", slow_start="", group_down_threshold="", group_restored_threshold="", backup="",
                 ids_group="", ids_chain="", group_flood="", real_port_metric="",
                 alert_on_server_failure_threshold="", workload_manager_id=None, dsr_vip_health_check="",
                 operator_access="", health_check_formula=None, overload_overflow_exception="",
                 radius_group_secret=None, real_servers=None,phash_mask=""):
        self.group_id = group_id
        self.description = description
        self.group_type = group_type
        self.ip_version = ip_version
        self.slb_metric = slb_metric
        self.health_check = health_check
        self.slow_start = slow_start
        self.group_down_threshold = group_down_threshold
        self.group_restored_threshold = group_restored_threshold
        self.backup = backup
        self.ids_group = ids_group
        self.ids_chain = ids_chain
        self.group_flood = group_flood
        self.real_port_metric = real_port_metric
        self.alert_on_server_failure_threshold = alert_on_server_failure_threshold
        self.workload_manager_id = workload_manager_id
        self.dsr_vip_health_check = dsr_vip_health_check
        self.operator_access = operator_access
        self.health_check_formula = health_check_formula
        self.overload_overflow_exception = overload_overflow_exception
        self.radius_group_secret = radius_group_secret
        self.real_servers = []
        self.phash_mask = phash_mask

    def get_phash_mask(self):
        return self.phash_mask

    def set_phash_mask(self, value):
        self.phash_mask = value

    # Example Getter
    def get_group_id(self):
        return self.group_id

    # Example Setter
    def set_group_id(self, value):
        self.group_id = value

    # You will need to create additional getters and setters for all other attributes
    def has_real_server(self, real_server_name):
        # Check if the group already contains a real server with the same service_member name
        return any(server['service_member'] == real_server_name for server in self.real_servers)

    def add_real_server(self, real_server):
        # Ensure the real server is not already in the group to avoid duplicates
        if not self.has_real_server(real_server['service_member']):
            self.real_servers.append(real_server)

    # def remove_real_server(self, server_id):
    #     self.real_servers_ids = real_servers_ids
    def get_real_server(self, real_server_name):
        # Retrieve a real server by its service_member name
        for server in self.real_servers:
            if server['service_member'] == real_server_name:
                return server
        return None

    def list_all_real_servers(self):
        return self.real_servers

    # Description
    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    # Group Type
    def get_group_type(self):
        return self.group_type

    def set_group_type(self, value):
        self.group_type = value

    # IP Version
    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    # SLB Metric
    def get_slb_metric(self):
        return self.slb_metric

    def set_slb_metric(self, value):
        self.slb_metric = value

    # Health Check
    def get_health_check(self):
        return self.health_check

    def set_health_check(self, value):
        self.health_check = value

    # Slow Start
    def get_slow_start(self):
        return self.slow_start

    def set_slow_start(self, value):
        self.slow_start = value

    # Group Down Threshold
    def get_group_down_threshold(self):
        return self.group_down_threshold

    def set_group_down_threshold(self, value):
        self.group_down_threshold = value

    # Group Restored Threshold
    def get_group_restored_threshold(self):
        return self.group_restored_threshold

    def set_group_restored_threshold(self, value):
        self.group_restored_threshold = value

    # Backup
    def get_backup(self):
        return self.backup

    def set_backup(self, value):
        self.backup = value

    # IDS Group
    def get_ids_group(self):
        return self.ids_group

    def set_ids_group(self, value):
        self.ids_group = value

    # IDS Chain
    def get_ids_chain(self):
        return self.ids_chain

    def set_ids_chain(self, value):
        self.ids_chain = value

    # Group Flood
    def get_group_flood(self):
        return self.group_flood

    def set_group_flood(self, value):
        self.group_flood = value

    # Real Port Metric
    def get_real_port_metric(self):
        return self.real_port_metric

    def set_real_port_metric(self, value):
        self.real_port_metric = value

    # Alert on Server Failure Threshold
    def get_alert_on_server_failure_threshold(self):
        return self.alert_on_server_failure_threshold

    def set_alert_on_server_failure_threshold(self, value):
        self.alert_on_server_failure_threshold = value

    # Workload Manager ID
    def get_workload_manager_id(self):
        return self.workload_manager_id

    def set_workload_manager_id(self, value):
        self.workload_manager_id = value

    # DSR VIP Health Check
    def get_dsr_vip_health_check(self):
        return self.dsr_vip_health_check

    def set_dsr_vip_health_check(self, value):
        self.dsr_vip_health_check = value

    # Operator Access
    def get_operator_access(self):
        return self.operator_access

    def set_operator_access(self, value):
        self.operator_access = value

    # Health Check Formula
    def get_health_check_formula(self):
        return self.health_check_formula

    def set_health_check_formula(self, value):
        self.health_check_formula = value

    # Overload/Overflow Exception
    def get_overload_overflow_exception(self):
        return self.overload_overflow_exception

    def set_overload_overflow_exception(self, value):
        self.overload_overflow_exception = value

    # RADIUS Group Secret
    def get_radius_group_secret(self):
        return self.radius_group_secret

    def set_radius_group_secret(self, value):
        self.radius_group_secret = value
