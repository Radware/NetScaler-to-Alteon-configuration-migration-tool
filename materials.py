import ipaddress
import re
import validators


def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def validate_ipv6(ip_address):
    try:
        ipaddress.IPv6Address(ip_address)
        return True
    except ValueError:
        return False


def validate_ipv4(ip_address):
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ValueError:
        return False


def is_ip_address(ip_address):
    """for both ipv4 and ipv6 -  validator"""
    try:
        if validate_ipv4(ip_address) or validate_ipv6(ip_address):
            return True
    except ValueError:
        return False


def is_fqdn(s):
    """
    Check if the string is a valid FQDN.

    An FQDN must:
    - Be at least two labels separated by dots (e.g., example.com).
    - Each label must start and end with a letter or a digit.
    - Labels may contain letters, digits, and hyphens.
    - The top-level domain (TLD) must be letters.
    """

    return validators.domain(s)


def validate_port(input_string):
    try:
        port = int(input_string)
        if not 1 <= port <= 65535:
            raise ValueError("Port number must be between 1 and 65535")
        return True
    except ValueError:
        return False


def is_app_service_exists(app_service):
    app_service_lst = [
        "Basic - SLB",
        "DNS",
        "FTP",
        "FTP - Data",
        "HTTP",
        "HTTPS",
        "IP",
        "LDAP",
        "POP3",
        "RTSP",
        "SCTP",
        "SIP",
        "SMTP",
        "SSL",
        "TFTP",
        "WTS"
    ]

    if app_service in app_service_lst:
        return True
    else:
        return False

def is_protocol_service_exists(protocol):
    protocol_service_lst = [
        "TCP",
        "TCP and UDP",
        "UDP",
        "UDP Stateless"

    ]
    if protocol in protocol_service_lst:
        return True
    else:
        return False


def is_add_lb_vserver_virt(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "lb" and split_line [2] == "vserver":
        return True
    else:
        return False


def is_bind_lb_vserver_no_policy(line):
    split_line = line.split(" ")
    if split_line[0] == "bind" and split_line[1] == "lb" and split_line [2] == "vserver" and "-policyName" not in line:
        return True
    else:
        return False


def is_bind_lb_vserver_with_policy(line):
    split_line = line.split(" ")
    if split_line[0] == "bind" and split_line[1] == "lb" and split_line [2] == "vserver" and "-policyName" in line:
        return True
    else:
        return False


def is_add_serviceGroup(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "serviceGroup":
        return True
    else:
        return False

def is_add_service(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "service":
        return True
    else:
        return False


def is_bind_serviceGroup_no_monitor(line):
    split_line = line.split(" ")
    if split_line[0] == "bind" and split_line[1] == "serviceGroup" and "-monitorName" not in line:
        return True
    else:
        return False


def is_bind_service_no_monitor(line):
    split_line = line.split(" ")
    if split_line[0] == "bind" and split_line[1] == "service" and "-monitorName" not in line:
        return True
    else:
        return False


def is_bind_ssl_profile_vserver(line):
    split_line = line.split(" ")
    if split_line[0] == "set" and split_line[1] == "ssl" and split_line [2] == "vserver":
        return True
    else:
        return False


def is_add_ssl_profile(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "ssl" and split_line [2] == "profile":
        return True
    else:
        return False


def is_add_server(line):
    split_line = line.split()
    if len(split_line) < 4:
        return False  # Ensure there are enough parts in the split line
    if split_line[0] == "add" and split_line[1] == "server" and is_valid_ip(split_line[3]):
        return True
    return False


def is_add_server_fqdn(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "server":
        if is_fqdn(split_line[3].strip()):
            return True


def is_add_responder_policy(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "responder" and split_line[2] == "policy":
        return True


def is_add_responder_action(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "responder" and split_line[2] == "action":
        return True


def is_bind_ssl_vserver(line):
    split_line = line.split(" ")
    if split_line[0] == "bind" and split_line[1] == "ssl" and split_line[2] == "vserver" and "-certkeyName" in line:
        return True


def is_link_ssl_certKey(line):
    split_line = line.split(" ")
    if split_line[0] == "link" and split_line[1] == "ssl" and split_line[2] == "certKey" :
        return True


def is_add_lb_monitor(line):
    split_line = line.split(" ")
    if split_line[0] == "add" and split_line[1] == "lb" and split_line[2] == "monitor":
        return True


def supported_attr_vserver(attr):
    for att in add_lb_vserver_flags:
        if att['netscaler_vserver_feature'] == attr:
            if att['alteon_support']:
                return True



def supported_attr_service(attr):
    for att in service_group_flags:
        if att['netscaler_vserver_feature'] == attr:
            if att['alteon_support']:
                return True


def supported_monitors(mon_type):
    for mon in supported_monitors_lst:
        if mon.lower() in mon_type.lower():
            return True
    return False

def get_unique_values(input_list):
    return list(set(input_list))


supported_monitors_lst = ["HTTP", "HTTPS", "TCP", "UDP", "ICMP", "ARP","HTTP2"]
#
# Feature mapping
#
add_server_real_server_map =[
            {"ns_feature_name": "domainResolveRetry", "supported_alt": False, "alt_feature_name": " "},
            {"ns_feature_name": "IPv6Address ", "supported_alt": False, "alt_feature_name": " "},
            {"ns_feature_name": "queryType", "supported_alt": False, "alt_feature_name": " "},
            {"ns_feature_name": "translationIp ", "supported_alt": True, "alt_feature_name": " "},
            {"ns_feature_name": "translationMask  ", "supported_alt": True, "alt_feature_name": " "},
            {"ns_feature_name": "state", "supported_alt": True, "alt_feature_name": " "},
            {"ns_feature_name": "comment", "supported_alt ": True, "alt_feature_name": " "},
            {"ns_feature_name": "td ", "supported_alt ": False, "alt_feature_name": " "},
            {"ns_feature_name": "server_name ", "supported_alt ": True, "alt_feature_name": " "},
            {"ns_feature_name": "ip_address ", "supported_alt ": True, "alt_feature_name": " "},
]



persistency_types_alteon_supported = {
                                                    'CALLID': 'unsupported',
                                                   'SOURCEIP': 'supported',
                                                   'COOKIEINSERT': 'supported',
                                                   'URLPASSIVE': 'supported',
                                                   'SRCIPDESTIP': 'unsupported',
                                                   'RULE': 'unsupported',
                                                   'CUSTOMSERVERID': 'unsupported',
                                                   'DESTIP': 'unsupported',
                                                   'RTSPSID': 'unsupported',
                                                   'FIXSESSION': 'unsupported',
                                                   'USERSESSION': 'unsupported',
                                                   'NONE': 'supported',
                                                   'SSLSESSION':'supported'
                                        }


lb_method_types_alteon_supported = {
                                                'ROUNDROBIN': 'supported',
                                                'LEASTCONNECTION': 'supported',
                                                'LEASTRESPONSETIME': 'supported',
                                                'URLHASH': 'unsupported',
                                                'DOMAINHASH': 'unsupported',
                                                'DESTINATIONIPHASH': 'unsupported',
                                                'SOURCEIPHASH': 'supported',
                                                'SRCIPDESTIPHASH': 'unsupported',
                                                'LEASTBANDWIDTH': 'supported',
                                                'LEASTPACKETS': 'unsupported',
                                                'TOKEN': 'unsupported',
                                                'SRCIPSRCPORTHASH': 'supported',# but on persistency
                                                'LRTM': 'unsupported',
                                                'CALLIDHASH': 'unsupported',
                                                'CUSTOMLOAD': 'unsupported',
                                                'LEASTREQUEST': 'unsupported',
                                                'AUDITLOGHASH': 'unsupported',
                                                'STATICPROXIMITY': 'unsupported',
                                                'USER_TOKEN': 'unsupported'
                                                    }




































service_mapping_to_ALT = [
    {"service" : "HTTP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "HTTP"},
    {"service" : "FTP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "FTP"},
    {"service" : "FTP-Data", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "FTP-Data"},
    {"service" : "TCP", "protocol":"TCP", "forceproxy":"False", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "UDP", "protocol":"UDP", "forceproxy":"False", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "SSL", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "HTTPS"},
    {"service" : "SSL_BRIDGE", "protocol":"TCP", "forceproxy":"False", "Supported": "True", "Application": "HTTPS"},
    {"service" : "SSL_TCP", "protocol":"TCP", "forceproxy":"false", "Supported": "True", "Application": "HTTPS"},
    {"service" : "DTLS", "protocol":"UDP", "forceproxy":"false", "Supported": "False"},
    {"service" : "DNS", "protocol":"UDP", "forceproxy":"True", "Supported": "True", "Application": "DNS"},
    {"service" : "DHCPRA", "protocol":"TCP", "forceproxy":"false", "Supported": "False"},
    {"service" : "ANY", "protocol":"both", "forceproxy":"false", "Supported": "True", "Application": "IP"},
    {"service" : "SIP_UDP", "protocol":"UDP", "forceproxy":"True", "Supported": "True", "Application": "SIP"},
    {"service" : "SIP_TCP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "SIP"},
    {"service" : "SIP_SSL", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "SIP"},
    {"service" : "DNS_TCP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "DNS"},
    {"service" : "RTSP", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "PUSH", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "SSL_PUSH", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "RADIUS", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "RDP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "MYSQL", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "MSSQL", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "DIAMETER", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "SSL_DIAMETER", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "TFTP", "protocol":"UDP", "forceproxy":"True", "Supported": "True", "Application": "TFTP"},
    {"service" : "ORACLE", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "SMPP", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "SYSLOGTCP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "SYSLOGUDP", "protocol":"UDP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "FIX", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "SSL_FIX", "protocol":"TCP", "forceproxy":"True", "Supported": "False"},
    {"service" : "PROXY", "protocol":"TCP and UDP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "USER_TCP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "USER_SSL_TCP", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "Basic-SLB"},
    {"service" : "QUIC", "protocol":"TCP", "forceproxy":"True", "Supported": "True", "Application": "HTTPS"},
    {"service": "IPFIX", "protocol": "TCP", "forceproxy": "True", "Supported": "False"},
    {"service": "LOGSTREAM", "protocol": "TCP", "forceproxy": "True", "Supported": "False"},
    {"service": "MONGO", "protocol": "TCP", "forceproxy": "True", "Supported": "True", "Application": "Basic-SLB"},
    {"service": "MONGO_TLS", "protocol": "TCP", "forceproxy": "True", "Supported": "True", "Application": "Basic-SLB"},
    {"service": "MQTT_TLS", "protocol": "TCP", "forceproxy": "True", "Supported": "False"},
    {"service": "QUIC_BRIDGE", "protocol": "TCP", "forceproxy": "True", "Supported": "False"},
    {"service": "HTTP_QUIC", "protocol": "TCP", "forceproxy": "True", "Supported": "True", "Application": "HTTPS"}

]

add_server_flags = [
    "-domainResolveRetry",
    "-IPv6Address",  # Values: YES, NO
    "-queryType",  # Values: A, AAAA, SRV
    "-translationIp",  # Requires <ip_addr>
    "-translationMask",  # Requires netmask value
    "-state",  # Values: ENABLED, DISABLED
    "-comment",  # Free text
    "-td",  # Requires a positive integer
]

service_group_flags = [

    {
        "netscaler_vserver_feature": "cacheType",
        "alteon_support": False,
        "message": "Unsupported for this tool"
    },
    {
        "netscaler_vserver_feature": "td",
        "alteon_support": False,
        "message": "Unsupported for this tool"
    },
    {
        "netscaler_vserver_feature": "maxClient",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "maxReq",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "cacheable",
        "alteon_support": False,
        "message": "Unsupported for thi tool"
    },
    {
        "netscaler_vserver_feature": "cip",
        "alteon_support": True,
        "message": "Unsupported this tool, there is option to send only XFF header",
        "alteon_feature_name": "xforward",
        "value_map": [
            {
                "netscaler_value": "ENABLED",
                "alteon_support": True,
                "alteon_value": "ena"
            },
            {
                "netscaler_value": "DISABLED",
                "alteon_support": True,
                "alteon_value": "dis"

            },

        ]
    },
    {
        "netscaler_vserver_feature": "cipHeader",
        "alteon_support": False,
        "message": "Unsupported this tool, there is option to send only XFF header other headers needs to be configured diffrently"
    },
    {
        "netscaler_vserver_feature": "usip",
        "alteon_support": True,
        "message": "supported",
        "alteon_feature_name": "pip mode disable",
        "value_map": [
            {
                "netscaler_value": "YES",
                "alteon_support": True,
                "alteon_value": "dis"
            },
            {
                "netscaler_value": "NO",
                "alteon_support": True,
                "alteon_value": "ingress"

            },

        ]
    },
    {
        "netscaler_vserver_feature": "pathMonitor",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "pathMonitorIndv",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "useproxyport",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "healthMonitor",
        "alteon_support": False,
        "message": "Unsupported - on Alteon you have to choose Health checks or define nocheck"
    },
    {
        "netscaler_vserver_feature": "sp",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "rtspSessionidRemap",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "cltTimeout",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "svrTimeout",
        "alteon_support": False,
        "message": "UnSupported",
    },
    {
        "netscaler_vserver_feature": "CKA",
        "alteon_support": True,
        "message": "Part of TCP optimization rules (enable-disable keep alive)",

    },
    {
        "netscaler_vserver_feature": "TCPB",
        "alteon_support": False,
        "message": "Default buffer size on alteon is 256K "
    },
    {
        "netscaler_vserver_feature": "CMP",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "maxBandwidth",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "monThreshold",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "state",
        "alteon_support": False,
        "message": "Unsupported - Service is always up if the monitor is up"

    },
    {
        "netscaler_vserver_feature": "downStateFlush",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "tcpProfileName",
        "alteon_support": False,
        "message": "Backend TCP profile",
        "alteon_feature_name": "betcppol"

    },
    {
        "netscaler_vserver_feature": "httpProfileName",
        "alteon_support": False,
        "message": "Unsupported for this tool"
    },
    {
        "netscaler_vserver_feature": "comment",
        "alteon_support": True,
        "message": "description / name",
        "alteon_feature_name": "name"
    },
    {
        "netscaler_vserver_feature": "appflowLog",
        "alteon_support": False,
        "message": "Unsupported for this tool, called Traffic event on Alteon"
    },
    {
        "netscaler_vserver_feature": "netProfile",
        "alteon_support": False,
        "message": "Unsupported for this tool, called Source Network on Alteon"
    },
    {
        "netscaler_vserver_feature": "autoScale",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "autoDisablegraceful",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "autoDisabledelay",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "autoDelayedTrofs",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "monConnectionClose",
        "alteon_support": False,
        "message": "Unsupported"
    }
]

add_lb_vserver_flags = [
    {
        "netscaler_vserver_feature": "persistenceType",
        "alteon_support": True,
        "message": "persistance  ",
        "alteon_feature_name": "pbind",
        "value_map": [
            {
                "netscaler_value": "SOURCEIP",
                "alteon_support": True,
                "alteon_value": "SOURCEIP"
            },
            {
                "netscaler_value": "CUSTOMSERVERID",
                "alteon_support": False,

            },
            {
                "netscaler_value": "COOKIEINSERT",
                "alteon_support": True,
                "alteon_value": 'cookie insert '
            },
            {
                "netscaler_value": "SSLSESSION",
                "alteon_support": True,
                "alteon_value": "sslidpbind"
            },
            {
                "netscaler_value": "RULE",
                "alteon_support": False,

            },
            {
                "netscaler_value": "URLPASSIVE",
                "alteon_support": False,
            },
            {
                "netscaler_value": "DESTIP",
                "alteon_support": False

            },
            {
                "netscaler_value": "SRCIPDESTIP",
                "alteon_support": False,
            },
            {
                "netscaler_value": "CALLID",
                "alteon_support": False,
            },
            {
                "netscaler_value": "RTSPSID",
                "alteon_support": False
            },

            {
                "netscaler_value": "FIXSESSION",
                "alteon_support": False
            },
            {
                "netscaler_value": "USERSESSION",
                "alteon_support": False
            },

        ]
    },
    {
        "netscaler_vserver_feature": "lbMethod",
        "alteon_support": True,
        "message": "Load  ",
        "alteon_feature_name": "metric",
        "value_map": [
            {
                "netscaler_value": "ROUNDROBIN",
                "alteon_support": True,
                "alteon_value": "roundrobin"
            },
            {
                "netscaler_value": "STATELESS",
                "alteon_support": False,

            },
            {
                "netscaler_value": "LEASTCONNECTION",
                "alteon_support": True,
                "alteon_value": "leastconns"
            },
            {
                "netscaler_value": "LEASTRESPONSETIME",
                "alteon_support": True,
                "alteon_value": "response"
            },
            {
                "netscaler_value": "LEASTBANDWIDTH",
                "alteon_support": True,
                "alteon_value": "bandwidth"
            },
            {
                "netscaler_value": "LEASTPACKETS",
                "alteon_support": False,

            },
            {
                "netscaler_value": "CUSTOMLOAD",
                "alteon_support": False,
            },
            {
                "netscaler_value": "LRTM",
                "alteon_support": False

            },
            {
                "netscaler_value": "URLHASH",
                "alteon_support": False,
            },
            {
                "netscaler_value": "DOMAINHASH",
                "alteon_support": False,
            },
            {
                "netscaler_value": "DESTINATIONIPHASH",
                "alteon_support": False
            },
            {
                "netscaler_value": "SOURCEIPHASH",
                "alteon_support": True,
                "alteon_value": "hash"
            },
            {
                "netscaler_value": "TOKEN",
                "alteon_support": False
            },
            {
                "netscaler_value": "SRCIPDESTIPHASH",
                "alteon_support": False
            },
            {
                "netscaler_value": "SRCIPSRCPORTHASH",
                "alteon_support": False
            },
            {
                "netscaler_value": "CALLIDHASH",
                "alteon_support": False
            },
            {
                "netscaler_value": "USER_TOKEN",
                "alteon_support": False
            }

        ]
         },
        {
            'netscaler_vserver_feature': 'persistenceBackup',
            'alteon_support': False,
            'message': 'Unsupported'
        },
        {
            'netscaler_vserver_feature': 'backupPersistenceTimeout',
            'alteon_support': False,
            'message': 'Unsupported'
        },
        {
            'netscaler_vserver_feature': 'hashLength',
            'alteon_support': True,
            'message': 'supported only for cookie based URL'
        },
        {
            'netscaler_vserver_feature': 'backupLBMethod',
            'alteon_support': False,
            'message': 'Unsupported'
        },
    {
        'netscaler_vserver_feature':'rule',
        'alteon_support': False,
        'message':'Unsupported'
    },
    {
        "netscaler_vserver_feature": "Listenpolicy",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "listenPriority",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "resRule",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "rtspNat",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "m",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "tosId",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "dataLength",
        "alteon_support": False,
        "message": "Token LB method is Unsupported"
    },
    {
        "netscaler_vserver_feature": "dataOffset",
        "alteon_support": False,
        "message": "Token LB method is Unsupported"
    },
    {
        "netscaler_vserver_feature": "sessionless",
        "alteon_support": True,
        "message": "Supported as nonat",
        "alteon_feature_name": "nonat",
        "value_map":[
            {
                "netscaler_value":"ENABLED",
                "alteon_support": True,
                "alteon_value": "ena"
            },
            {
                "netscaler_value": "DISABLED",
                "alteon_support": True,
                "alteon_value": "dis"
            }
        ]

    },
    {
        "netscaler_vserver_feature": "trofsPersistence",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "connfailover",
        "alteon_support": True,
        "message": "Alteon support either ena or dis ",
        "alteon_feature_name": "mirror",
        "value_map":[
            {
                "netscaler_value":"STATEFUL",
                "alteon_support": True,
                "alteon_value": "ena"
            },
            {
                "netscaler_value":"STATELESS",
                "alteon_support": False,

            },
            {
                "netscaler_value": "DISABLED",
                "alteon_support": True,
                "alteon_value": "dis"
            }
        ]
    },
    {
        "netscaler_vserver_feature": "redirectURL",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "cacheable",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "soMethod",
        "alteon_support": False,
        "message": "Spill over is Unsupported"
    },
    {
        "netscaler_vserver_feature": "soPersistence",
        "alteon_support": False,
        "message": "Spill over is Unsupported"
    },
    {
        "netscaler_vserver_feature": "soPersistenceTimeOut",
        "alteon_support": False,
        "message": "Spill over is Unsupported"
    },
    {
        "netscaler_vserver_feature": "healthThreshold",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "soThreshold",
        "alteon_support": False,
        "message": "Spill over is Unsupported"
    },
    {
        "netscaler_vserver_feature": "soBackupAction",
        "alteon_support": False,
        "message": "Spill over is Unsupported"
    },
    {
        "netscaler_vserver_feature": "redirectPortRewrite",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "downStateFlush",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "disablePrimaryOnDown",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "insertVserverIPPort",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "vipHeader",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "AuthenticationHost",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "Authentication",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "authn401",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "authnVsName",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "push",
        "alteon_support": False,
        "message": "push is Unsupported"
    },
    {
        "netscaler_vserver_feature": "pushVserver",
        "alteon_support": False,
        "message": "push is Unsupported"
    },
    {
        "netscaler_vserver_feature": "pushLabel",
        "alteon_support": False,
        "message": "push is Unsupported"
    },
    {
        "netscaler_vserver_feature": "pushMultiClients",
        "alteon_support": False,
        "message": "push is Unsupported"
    },
    {
        "netscaler_vserver_feature": "dbProfileName",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "l2Conn",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "oracleServerVersion",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "mssqlServerVersion",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "mysqlProtocolVersion",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "mysqlServerVersion",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "mysqlCharacterSet",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "mysqlServerCapabilities",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "appflowLog",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "icmpVsrResponse",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "RHIstate",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "newServiceRequest",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "newServiceRequestUnit",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "newServiceRequestIncrementInterval",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "minAutoscaleMembers",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "persistAVPno",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "skippersistency",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "td",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "authnProfile",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "macmodeRetainvlan",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "dbsLb",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "dns64",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "bypassAAAA",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "RecursionAvailable",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "processLocal",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "dnsProfileName",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "lbprofilename",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "redirectFromPort",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "httpsRedirectUrl",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "retainConnectionsOnCluster",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "adfsProxyProfile",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "quicBridgeProfilename",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "probeProtocol",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "probeSuccessResponseCode",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "probePort",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "toggleorder",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "orderthreshold",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "timeout",
        "alteon_support": True,
        "message": "Unsupported",
        "alteon_feature_name": "tmout"
    },
    {
        "netscaler_vserver_feature": "netmask",
        "alteon_support": True,
        "message": "supported",
        "alteon_feature_name": "metric phash"
    },
    {
        "netscaler_vserver_feature": "v6netmasklen",
        "alteon_support": True,
        "message": "supported",
        "alteon_feature_name": "metric phash"
    },
    {
        "netscaler_vserver_feature": "cookieName",
        "alteon_support": True,
        "message": "supported",

    },
    {
        "netscaler_vserver_feature": "persistMask",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "v6persistmasklen",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "state",
        "alteon_support": True,
        "message": "supported",
        "alteon_feature_name": "",
        "value_map":[
            {
                "netscaler_value":"ENABLED",
                "alteon_support": True,
                "alteon_value": "ena"
            },
            {
                "netscaler_value": "DISABLED",
                "alteon_support": True,
                "alteon_value": "dis"
            }
        ]

    },
    {
        "netscaler_vserver_feature": "cltTimeout",
        "alteon_support": True,
        "message": "Supported"


    },
    {
        "netscaler_vserver_feature": "tcpProfileName",
        "alteon_support": False,
        "message": "FrontEnd optimization policy",
        "alteon_feature_name": "tcppol"
    },
    {
        "netscaler_vserver_feature": "httpProfileName",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "comment",
        "alteon_support": True,
        "message": "Description",
        "alteon_feature_name": "vname"
    },
    {
        "netscaler_vserver_feature": "netProfile",
        "alteon_support": False,
        "message": "Unsupported"
    },
    {
        "netscaler_vserver_feature": "quicProfileName",
        "alteon_support": False,
        "message": "Unsupported"
    }
]