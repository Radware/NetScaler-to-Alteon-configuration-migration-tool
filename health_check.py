class Monitor:
    """Monitor class  - to have a ability to create and change common Health Monitors
        currently, this class supports : TCP, UDP, HTTP, HTTPS ,ICMP,ARP AND DNS.
    """

    def __init__(self, name, monitor_type):
        self.name = name
        self.monitor_type = monitor_type

    def get_name(self):
        return self.name

    def set_name(self, value):
        self.name = value

    def get_monitor_type(self):
        return self.monitor_type

    def set_monitor_type(self, value):
        self.monitor_type = value


class ARPMonitor(Monitor):
    def __init__(self, name, arp_id="arp", description="", destination_ip="none", invert_result="Disabled",
                 interval=5, retries_to_failure=4, retries_to_restore=2, response_timeout=0, check_interval_downtime=0):
        super().__init__(name, "ARP")  # "ARP" is the monitor_type for ARPMonitor
        self.arp_id = arp_id
        self.description = description
        self.destination_ip = destination_ip
        self.invert_result = invert_result
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.check_interval_downtime = check_interval_downtime

    # ARP ID
    def get_arp_id(self):
        return self.arp_id

    def set_arp_id(self, value):
        self.arp_id = value

    # Description
    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    # Destination IP
    def get_destination_ip(self):
        return self.destination_ip

    def set_destination_ip(self, value):
        self.destination_ip = value

    # Invert Result
    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    # Interval
    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    # Retries to Failure
    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, value):
        self.retries_to_failure = value

    # Retries to Restore
    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    # Response Timeout
    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    # Checks Interval on Down-Time
    def get_check_interval_downtime(self):
        return self.check_interval_downtime

    def set_check_interval_downtime(self, value):
        self.check_interval_downtime = value

    def list_all_attributes(self):
        """Prints all the attributes of the ARPMonitor instance."""
        attributes = {
            'Monitor Name': self.name,
            'Monitor Type': self.monitor_type,
            'ARP ID': self.arp_id,
            'Description': self.description,
            'Destination IP Address': self.destination_ip,
            'Invert Result': self.invert_result,
            'Interval': self.interval,
            'Retries to Failure': self.retries_to_failure,
            'Retries to Restore': self.retries_to_restore,
            'Response Timeout': self.response_timeout,
            'Checks Interval on Down-Time': self.check_interval_downtime,
        }
        for attr, value in attributes.items():
            print(f"{attr}: {value}")


class DNSMonitor(Monitor):
    def __init__(self, name, protocol="TCP", port=53, ip_version="IPv4", description="", destination_ip="none",
                 invert_result=False, transparent_health_check=False, domain="inherit", interval=5,
                 retries_to_failure=4, retries_to_restore=2, response_timeout=0, check_interval_downtime=0):
        super().__init__(name, "DNS")
        self.protocol = protocol
        self.port = port
        self.ip_version = ip_version
        self.description = description
        self.destination_ip = destination_ip
        self.invert_result = invert_result
        self.transparent_health_check = transparent_health_check
        self.domain = domain
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.check_interval_downtime = check_interval_downtime

    # Protocol
    def get_protocol(self):
        return self.protocol

    def set_protocol(self, value):
        self.protocol = value

    # Port
    def get_port(self):
        return self.port

    def set_port(self, value):
        self.port = value

    # IP Version
    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    # Description
    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    # Destination IP
    def get_destination_ip(self):
        return self.destination_ip

    def set_destination_ip(self, value):
        self.destination_ip = value

    # Invert Result
    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    # Transparent Health Check
    def get_transparent_health_check(self):
        return self.transparent_health_check

    def set_transparent_health_check(self, value):
        self.transparent_health_check = value

    # Domain
    def get_domain(self):
        return self.domain

    def set_domain(self, value):
        self.domain = value

    # Interval
    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    # Retries to Failure
    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, value):
        self.retries_to_failure = value

    # Retries to Restore
    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    # Response Timeout
    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    # Checks Interval on Downtime
    def get_check_interval_downtime(self):
        return self.check_interval_downtime

    def set_check_interval_downtime(self, value):
        self.check_interval_downtime = value

    def list_all_attributes(self):
        """Prints all the attributes of the DNSMonitor instance."""
        attributes = {
            'Monitor Name': self.name,
            'Monitor Type': self.monitor_type,
            'Protocol': self.protocol,
            'Port': self.port,
            'IP Version': self.ip_version,
            'Destination IP Address': self.destination_ip,
            'Invert Result': self.invert_result,
            'Transparent Health Check': self.transparent_health_check,
            'Domain': self.domain,
            'Interval': self.interval,
            'Retries to Failure': self.retries_to_failure,
            'Retries to Restore': self.retries_to_restore,
            'Response Timeout': self.response_timeout,
            'Checks Interval on Down-Time': self.check_interval_on_downtime,
        }
        for attr, value in attributes.items():
            print(f"{attr}: {value}")

class FTPMonitor(Monitor):
    def __init__(self, name, ftp_id="ftp", description="", destination_port=None, ip_version="IPv4",
                 destination_ip=None, invert_result=False, transparent_health_check=False,
                 username="anonymous", password=None, path_filename="inherit", interval=5,
                 retries_to_failure=4, retries_to_restore=2, response_timeout=0, check_interval_downtime=0):
        super().__init__(name, "FTP")
        self.ftp_id = ftp_id
        self.description = description
        self.destination_port = destination_port
        self.ip_version = ip_version
        self.destination_ip = destination_ip
        self.invert_result = invert_result
        self.transparent_health_check = transparent_health_check
        self.username = username
        self.password = password
        self.path_filename = path_filename
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.check_interval_downtime = check_interval_downtime

    # FTP ID
    def get_ftp_id(self):
        return self.ftp_id

    def set_ftp_id(self, value):
        self.ftp_id = value

    # Description
    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    # Destination Port
    def get_destination_port(self):
        return self.destination_port

    def set_destination_port(self, value):
        self.destination_port = value

    # IP Version
    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    # Destination IP
    def get_destination_ip(self):
        return self.destination_ip

    def set_destination_ip(self, value):
        self.destination_ip = value

    # Invert Result
    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    # Transparent Health Check
    def get_transparent_health_check(self):
        return self.transparent_health_check

    def set_transparent_health_check(self, value):
        self.transparent_health_check = value

    # Username
    def get_username(self):
        return self.username

    def set_username(self, value):
        self.username = value

    # Password
    def get_password(self):
        return self.password

    def set_password(self, value):
        self.password = value

    # Path/Filename
    def get_path_filename(self):
        return self.path_filename

    def set_path_filename(self, value):
        self.path_filename = value

    # Interval
    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    # Retries to Failure
    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, value):
        self.retries_to_failure = value

    # Retries to Restore
    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    # Response Timeout
    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    # Checks Interval on Down-Time
    def get_check_interval_downtime(self):
        return self.check_interval_downtime

    def set_check_interval_downtime(self, value):
        self.check_interval_downtime = value


class HTTPMonitor(Monitor):
    def __init__(self, name, http_id="http", description="", https="Disabled", destination_port="none",
                 ip_version="IPv4", destination_ip="", invert_result="Disabled",
                 transparent_health_check="Disabled", connection_termination="FIN",
                 always_perform_health_check="Disable", method="GET", hostname="inherit",
                 path="inherit", http2="Disabled", header="", body="", authentication="None",
                 proxy_request="Disabled", expected_return_codes="200", return_string_type="None",expected_return_string="None",
                 overload_type="None", interval=5, retries_to_failure=4,
                 retries_to_restore=2, response_timeout=0, checks_interval_on_downtime=0):
        super().__init__(name, "HTTP")  # "HTTP" is the monitor_type for HTTPMonitor
        self.http_id = http_id
        self.description = description
        self.https = https
        self.destination_port = destination_port
        self.ip_version = ip_version
        self.destination_ip = destination_ip
        self.invert_result = invert_result
        self.transparent_health_check = transparent_health_check
        self.connection_termination = connection_termination
        self.always_perform_health_check = always_perform_health_check
        self.method = method
        self.hostname = hostname
        self.path = path
        self.http2 = http2
        self.header = header
        self.body = body
        self.authentication = authentication
        self.proxy_request = proxy_request
        self.expected_return_codes = expected_return_codes
        self.return_string_type = return_string_type
        self.overload_type = overload_type
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.checks_interval_on_downtime = checks_interval_on_downtime
        self.expected_return_string = expected_return_string

    # Getters and Setters for each attribute
    def get_http_id(self):
        return self.http_id

    def set_http_id(self, value):
        self.http_id = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_https(self):
        return self.https

    def set_https(self, value):
        self.https = value

    def get_destination_port(self):
        return self.destination_port

    def set_destination_port(self, value):
        self.destination_port = value

    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    def get_destination_ip(self):
        return self.destination_ip

    def set_destination_ip(self, value):
        self.destination_ip = value

    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    def get_transparent_health_check(self):
        return self.transparent_health_check

    def set_transparent_health_check(self, value):
        self.transparent_health_check = value

    def get_connection_termination(self):
        return self.connection_termination

    def set_connection_termination(self, value):
        self.connection_termination = value

    def get_always_perform_health_check(self):
        return self.always_perform_health_check

    def set_always_perform_health_check(self, value):
        self.always_perform_health_check = value

    def get_method(self):
        return self.method

    def set_method(self, value):
        self.method = value

    def get_hostname(self):
        return self.hostname

    def set_hostname(self, value):
        self.hostname = value

    def get_path(self):
        return self.path

    def set_path(self, value):
        self.path = value

    def get_http2(self):
        return self.http2

    def set_http2(self, value):
        self.http2 = value

    def get_header(self):
        return self.header

    def set_header(self, value):
        self.header = value

    def get_body(self):
        return self.body

    def set_body(self, value):
        self.body = value

    def get_authentication(self):
        return self.authentication

    def set_authentication(self, value):
        self.authentication = value

    def get_proxy_request(self):
        return self.proxy_request

    def set_proxy_request(self, value):
        self.proxy_request = value

    def get_expected_return_codes(self):
        return self.expected_return_codes

    def set_expected_return_codes(self, value):
        self.expected_return_codes = value

    def get_return_string_type(self):
        return self.return_string_type

    def set_return_string_type(self, value):
        self.return_string_type = value

    def get_overload_type(self):
        return self.overload_type

    def set_overload_type(self, value):
        self.overload_type = value

    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, value):
        self.retries_to_failure = value

    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    def get_checks_interval_on_downtime(self):
        return self.checks_interval_on_downtime

    def set_checks_interval_on_downtime(self, value):
        self.checks_interval_on_downtime = value

    def get_expected_return_string(self):
        return self.expected_return_string

    def set_expected_return_string(self, value):
        self.expected_return_string = value


class HTTPSMonitor(HTTPMonitor):
    def __init__(self, name, http_id="https", description="", https="Enabled", destination_port="none",
                 ip_version="IPv4", destination_ip="", invert_result="Disabled",
                 transparent_health_check="Disabled", connection_termination="FIN",
                 always_perform_health_check="Disable", method="GET", hostname="inherit",
                 path="inherit", http2="Disabled", header="", body="", authentication="None",
                 proxy_request="Disabled", expected_return_codes="200", return_string_type="None",
                 overload_type="None", interval=5, retries_to_failure=4,
                 retries_to_restore=2, response_timeout=0, checks_interval_on_downtime=0,
                 cipher="DEFAULT"):

        super().__init__(name=name, http_id=http_id, description=description, https=https,
                         destination_port=destination_port, ip_version=ip_version,
                         destination_ip=destination_ip, invert_result=invert_result,
                         transparent_health_check=transparent_health_check,
                         connection_termination=connection_termination,
                         always_perform_health_check=always_perform_health_check,
                         method=method, hostname=hostname, path=path, http2=http2,
                         header=header, body=body, authentication=authentication,
                         proxy_request=proxy_request, expected_return_codes=expected_return_codes,
                         return_string_type=return_string_type, overload_type=overload_type,
                         interval=interval, retries_to_failure=retries_to_failure,
                         retries_to_restore=retries_to_restore,
                         response_timeout=response_timeout,
                         checks_interval_on_downtime=checks_interval_on_downtime)

        # Set any additional attributes specific to HTTPS
        self.cipher = cipher

    # Additional getters and setters for HTTPS-specific attributes
    def get_cipher(self):
        return self.cipher

    def set_cipher(self, value):
        self.cipher = value


class TCPMonitor(Monitor):
    def __init__(self, tcp_id="tcp", description="", ip_version=None, destination_port=None,
                 invert_result="Disabled", transparent_health_check="Disabled",
                 connection_termination="FIN", always_perform_health_check="Disable",
                 interval=5, retries_to_failure=4, retries_to_restore=2,
                 response_timeout=0, checks_interval_on_downtime=0):
        super().__init__(tcp_id, "TCP")
        self.tcp_id = tcp_id
        self.name = tcp_id
        self.description = description
        self.ip_version = ip_version
        self.destination_port = destination_port
        self.invert_result = invert_result
        self.transparent_health_check = transparent_health_check
        self.connection_termination = connection_termination
        self.always_perform_health_check = always_perform_health_check
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.checks_interval_on_downtime = checks_interval_on_downtime

    # Getters and setters
    def get_tcp_id(self):
        return self.tcp_id

    def set_tcp_id(self, value):
        self.tcp_id = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    def get_destination_port(self):
        return self.destination_port

    def set_destination_port(self, value):
        self.destination_port = value

    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    def get_transparent_health_check(self):
        return self.transparent_health_check

    def set_transparent_health_check(self, value):
        self.transparent_health_check = value

    def get_connection_termination(self):
        return self.connection_termination

    def set_connection_termination(self, value):
        self.connection_termination = value

    def get_always_perform_health_check(self):
        return self.always_perform_health_check

    def set_always_perform_health_check(self, value):
        self.always_perform_health_check = value

    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, value):
        self.retries_to_failure = value

    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    def get_checks_interval_on_downtime(self):
        return self.checks_interval_on_downtime

    def set_checks_interval_on_downtime(self, value):
        self.checks_interval_on_downtime = value


class UDPMonitor(Monitor):
    def __init__(self, name, udp_id="udp", description="", destination_port="none",
                 ip_version="IPv4", destination_ip="", invert_result="Disabled",
                 transparent_health_check="Disabled", padding_to_64_bytes="Enabled",
                 interval=5, retries_to_failure=4, retries_to_restore=2, response_timeout=0,
                 checks_interval_on_downtime=0):
        super().__init__(name, "UDP")  # "UDP" is the monitor_type for UDPMonitor
        self.udp_id = udp_id
        self.description = description
        self.destination_port = destination_port
        self.ip_version = ip_version
        self.destination_ip = destination_ip
        self.invert_result = invert_result
        self.transparent_health_check = transparent_health_check
        self.padding_to_64_bytes = padding_to_64_bytes
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.checks_interval_on_downtime = checks_interval_on_downtime

    def get_udp_id(self):
        return self.udp_id

    def set_udp_id(self, value):
        self.udp_id = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_destination_port(self):
        return self.destination_port

    def set_destination_port(self, value):
        self.destination_port = value

    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    def get_destination_ip(self):
        return self.destination_ip

    def set_destination_ip(self, value):
        self.destination_ip = value

    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    def get_transparent_health_check(self):
        return self.transparent_health_check

    def set_transparent_health_check(self, value):
        self.transparent_health_check = value

    def get_padding_to_64_bytes(self):
        return self.padding_to_64_bytes

    def set_padding_to_64_bytes(self, value):
        self.padding_to_64_bytes = value

    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, value):
        self.retries_to_failure = value

    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    def get_checks_interval_on_downtime(self):
        return self.checks_interval_on_downtime

    def set_checks_interval_on_downtime(self, value):
        self.checks_interval_on_downtime = value

class ICMPMonitor(Monitor):
    def __init__(self, name, icmp_id="icmp", description="", ip_version="IPv4",
                 destination_ip="none", invert_result="Disabled",
                 transparent_health_check="Disabled", interval=5, retries_to_failure=4,
                 retries_to_restore=2, response_timeout=0, checks_interval_on_downtime=0):
        super().__init__(name, "ICMP")
        self.icmp_id = icmp_id
        self.description = description
        self.ip_version = ip_version
        self.destination_ip = destination_ip
        self.invert_result = invert_result
        self.transparent_health_check = transparent_health_check
        self.interval = interval
        self.retries_to_failure = retries_to_failure
        self.retries_to_restore = retries_to_restore
        self.response_timeout = response_timeout
        self.checks_interval_on_downtime = checks_interval_on_downtime

    def get_icmp_id(self):
        return self.icmp_id

    def set_icmp_id(self, value):
        self.icmp_id = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_ip_version(self):
        return self.ip_version

    def set_ip_version(self, value):
        self.ip_version = value

    def get_destination_ip(self):
        return self.destination_ip

    def set_destination_ip(self, value):
        self.destination_ip = value

    def get_invert_result(self):
        return self.invert_result

    def set_invert_result(self, value):
        self.invert_result = value

    def get_transparent_health_check(self):
        return self.transparent_health_check

    def set_transparent_health_check(self, value):
        self.transparent_health_check = value

    def get_interval(self):
        return self.interval

    def set_interval(self, value):
        self.interval = value

    def get_retries_to_failure(self):
        return self.retries_to_failure

    def set_retries_to_failure(self, retries_to_failure):
        self.retries_to_failure = retries_to_failure

    def get_retries_to_restore(self):
        return self.retries_to_restore

    def set_retries_to_restore(self, value):
        self.retries_to_restore = value

    def get_response_timeout(self):
        return self.response_timeout

    def set_response_timeout(self, value):
        self.response_timeout = value

    def get_checks_interval_on_downtime(self):
        return self.checks_interval_on_downtime

    def set_checks_interval_on_downtime(self, value):
        self.checks_interval_on_downtime = value