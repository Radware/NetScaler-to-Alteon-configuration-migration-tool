class Service:
    def __init__(self, service_id="", application="", service_port="", protocol="", action="", group_id='', real_server_port="0",
                 description='', hostname='', nameserver_groups='', delayed_binding='dis',
                 persistency_mode='dis', persistency_timeout=0, client_nat_mode='ingress',
                 https_redirect='dis', connection_handling_on_service_down='Drop', session_timeout="0",
                 send_rst_on_connection_close='dis', zero_window_size_in_syn_ack='dis',
                 close_session_on_slowaging='dis', close_session_on_fastaging='dis',
                 traffic_contract="1024", http_modification_rule_list='', script_association='',
                 service_always_up='dis', client_proximity_type='None', bandwidth_traffic_control="1024",
                 bwm_contract_per_string='', server_cloaking=False, error_code_update=False,
                 url_changes=False, url_path_obfuscation=False, free_text_replacement=False,
                 service_cluster=False, eert_active_attackers_feed=False, eaaf_in_cdn_deployment=False,
                 ip_address_header='x-forwarded-for', sideband_policy_id='', logging_and_reporting=False,
                 traffic_event_log_policy='', counter_based_reporting='Include this Service',
                 granularity_level_for_dpm='Virtual Service', defense_messaging_policy='',
                 satisfied_response_time_threshold='inherit',TCPFrontend='default',TCPBackend='default', redirect_string="", virt_assoiciate ="",
                 persist_cookie_insert="",persist_cookie_passive="",nonat="", mirror='dis', pip="", insert_xff="",ssl_policy_name ="", ssl_certificate=""):

        self.service_id = service_id
        self.application = application
        self.service_port = service_port
        self.protocol = protocol
        self.action = action
        self.group_id = group_id
        self.real_server_port = real_server_port
        self.description = description
        self.hostname = hostname
        self.nameserver_groups = nameserver_groups
        self.delayed_binding = delayed_binding
        self.persistency_mode = persistency_mode
        self.persistency_timeout = persistency_timeout
        self.client_nat_mode = client_nat_mode
        self.https_redirect = https_redirect
        self.connection_handling_on_service_down = connection_handling_on_service_down
        self.session_timeout = session_timeout
        self.send_rst_on_connection_close = send_rst_on_connection_close
        self.zero_window_size_in_syn_ack = zero_window_size_in_syn_ack
        self.close_session_on_slowaging = close_session_on_slowaging
        self.close_session_on_fastaging = close_session_on_fastaging
        self.traffic_contract = traffic_contract
        self.http_modification_rule_list = http_modification_rule_list
        self.script_association = script_association
        self.service_always_up = service_always_up
        self.client_proximity_type = client_proximity_type
        self.bandwidth_traffic_control = bandwidth_traffic_control
        self.bwm_contract_per_string = bwm_contract_per_string
        self.server_cloaking = server_cloaking
        self.error_code_update = error_code_update
        self.url_changes = url_changes
        self.url_path_obfuscation = url_path_obfuscation
        self.free_text_replacement = free_text_replacement
        self.service_cluster = service_cluster
        self.eert_active_attackers_feed = eert_active_attackers_feed
        self.eaaf_in_cdn_deployment = eaaf_in_cdn_deployment
        self.ip_address_header = ip_address_header
        self.sideband_policy_id = sideband_policy_id
        self.logging_and_reporting = logging_and_reporting
        self.traffic_event_log_policy = traffic_event_log_policy
        self.counter_based_reporting = counter_based_reporting
        self.granularity_level_for_dpm = granularity_level_for_dpm
        self.defense_messaging_policy = defense_messaging_policy
        self.satisfied_response_time_threshold = satisfied_response_time_threshold
        self.TCPFrontend = TCPFrontend
        self.TCPBackend = TCPBackend
        self.redirect_string = redirect_string
        self.virt_assoiciate = virt_assoiciate
        self.persist_cookie_insert = persist_cookie_insert
        self.persist_cookie_passive = persist_cookie_passive
        self.nonat = nonat
        self.mirror = mirror
        self.pip = pip
        self.insert_xff = insert_xff
        self.ssl_policy_name = ssl_policy_name
        self.ssl_certificate = ssl_certificate


    def get_ssl_certificate(self):
        return self.ssl_certificate

    def set_get_ssl_certificate(self, value):
        self.ssl_certificate = value

    def get_ssl_policy_name(self):
        return self.ssl_policy_name

    def set_ssl_policy_name(self, value):
        self.ssl_policy_name = value

    def get_insert_xff(self):
        return self.insert_xff

    def set_insert_xff(self, value):
        self.insert_xff = value

    def get_pip(self):
        return self.pip

    def set_pip(self, value):
        self.pip = value

    def get_mirror(self):
        return self.mirror

    def set_mirror(self, value):
        self.mirror = value

    def get_nonat(self):
        return self.nonat

    def set_not_nat(self, value):
        self.nonat = value

    def get_virt_assoiciate(self):
        return self.virt_assoiciate

    def set_virt_assoiciate(self, value):
        self.virt_assoiciate = value

    def get_persist_cookie_passive(self):
        return self.persist_cookie_passive

    def set_persist_cookie_passive(self, value):
        self.persist_cookie_passive = value

    def get_persist_cookie_insert(self):
        return self.persist_cookie_insert

    def set_persist_cookie_insert(self, value):
        self.persist_cookie_insert = value

    def get_redirect_string(self):
        return self.redirect_string

    def set_redirect_string(self, value):
        self.redirect_string = value

    def get_TCPFrontend(self):
        return self.TCPFrontend

    def set_TCPFrontend(self, value):
        self.TCPFrontend = value

    def get_TCPBackend(self):
        return self.TCPBackend

    def set_TCPBackend(self, value):
        self.TCPBackend = value

    def get_service_id(self):
        return self.service_id

    def set_service_id(self, value):
        self.service_id = value

    def get_application(self):
        return self.application

    def set_application(self, value):
        self.application = value

    def get_service_port(self):
        return self.service_port

    def set_service_port(self, value):
        self.service_port = value

    def get_protocol(self):
        return self.protocol

    def set_protocol(self, value):
        self.protocol = value

    def get_action(self):
        return self.action

    def set_action(self, value):
        self.action = value

    def get_group_id(self):
        return self.group_id

    def set_group_id(self, value):
        self.group_id = value

    def get_real_server_port(self):
        return self.real_server_port

    def set_real_server_port(self, value):
        self.real_server_port = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_hostname(self):
        return self.hostname

    def set_hostname(self, value):
        self.hostname = value

    def get_nameserver_groups(self):
        return self.nameserver_groups

    def set_nameserver_groups(self, value):
        self.nameserver_groups = value

    def get_delayed_binding(self):
        return self.delayed_binding

    def set_delayed_binding(self, value):
        self.delayed_binding = value

    def get_persistency_mode(self):
        return self.persistency_mode

    def set_persistency_mode(self, value):
        self.persistency_mode = value

    def get_persistency_timeout(self):
        return self.persistency_timeout

    def set_persistency_timeout(self, value):
        self.persistency_timeout = value

    def get_client_nat_mode(self):
        return self.client_nat_mode

    def set_client_nat_mode(self, value):
        self.client_nat_mode = value

    def get_http_redirect(self):
        return self.http_redirect

    def set_http_redirect(self, value):
        self.http_redirect = value

    def get_session_timeout(self):
        return self.session_timeout

    def set_session_timeout(self, value):
        self.session_timeout = value

    def get_send_rst_on_connection_close(self):
        return self.send_rst_on_connection_close

    def set_send_rst_on_connection_close(self, value):
        self.send_rst_on_connection_close = value

    def get_zero_window_size_in_syn_ack(self):
        return self.zero_window_size_in_syn_ack

    def set_zero_window_size_in_syn_ack(self, value):
        self.zero_window_size_in_syn_ack = value

    def get_close_session_on_slowaging(self):
        return self.close_session_on_slowaging

    def set_close_session_on_slowaging(self, value):
        self.close_session_on_slowaging = value

    def get_close_session_on_fastaging(self):
        return self.close_session_on_fastaging

    def set_close_session_on_fastaging(self, value):
        self.close_session_on_fastaging = value

    def get_bandwidth_management_control(self):
        return self.bandwidth_management_control

    def set_bandwidth_management_control(self, value):
        self.bandwidth_management_control = value

    def get_direct_server_return(self):
        return self.direct_server_return

    def set_direct_server_return(self, value):
        self.direct_server_return = value

    def get_direct_access_mode(self):
        return self.direct_access_mode

    def set_direct_access_mode(self, value):
        self.direct_access_mode = value

    def get_hash_selection(self):
        return self.hash_selection

    def set_hash_selection(self, value):
        self.hash_selection = value

    def get_return_to_source_tunnel(self):
        return self.return_to_source_tunnel

    def set_return_to_source_tunnel(self, value):
        self.return_to_source_tunnel = value

    def get_service_cluster(self):
        return self.service_cluster

    def set_service_cluster(self, value):
        self.service_cluster = value

    def get_ert_active_attackers_feed(self):
        return self.ert_active_attackers_feed

    def set_ert_active_attackers_feed(self, value):
        self.ert_active_attackers_feed = value

    def get_eaaf_in_cdn_deployment(self):
        return self.eaaf_in_cdn_deployment

    def set_eaaf_in_cdn_deployment(self, value):
        self.eaaf_in_cdn_deployment = value

    def get_ip_address_header(self):
        return self.ip_address_header

    def set_ip_address_header(self, value):
        self.ip_address_header = value

    def get_sideband_policy_id(self):
        return self.sideband_policy_id

    def set_sideband_policy_id(self, value):
        self.sideband_policy_id = value

    def get_logging_and_reporting(self):
        return self.logging_and_reporting

    def set_logging_and_reporting(self, value):
        self.logging_and_reporting = value

    def get_session_mirroring(self):
        return self.session_mirroring

    def set_session_mirroring(self, value):
        self.session_mirroring = value

    def get_session_logging(self):
        return self.session_logging

    def set_session_logging(self, value):
        self.session_logging = value

    def get_application_id(self):
        return self.application_id

    def set_application_id(self, value):
        self.application_id = value

    def get_traffic_event_log_policy(self):
        return self.traffic_event_log_policy

    def set_traffic_event_log_policy(self, value):
        self.traffic_event_log_policy = value

    def get_counter_based_reporting(self):
        return self.counter_based_reporting

    def set_counter_based_reporting(self, value):
        self.counter_based_reporting = value

    def get_granularity_level_for_dpm(self):
        return self.granularity_level_for_dpm

    def set_granularity_level_for_dpm(self, value):
        self.granularity_level_for_dpm = value

    def get_defense_messaging_policy(self):
        return self.defense_messaging_policy

    def set_defense_messaging_policy(self, value):
        self.defense_messaging_policy = value

    def get_satisfied_response_time_threshold(self):
        return self.satisfied_response_time_threshold

    def set_satisfied_response_time_threshold(self, value):
        self.satisfied_response_time_threshold = value

    def get_persistence_mode(self):
        return self.persistence_mode

    def set_persistence_mode(self, value):
        self.persistence_mode = value

    def get_persistence_timeout(self):
        return self.persistence_timeout

    def set_persistence_timeout(self, value):
        self.persistence_timeout = value

    def get_insert_x_forwarded_for(self):
        return self.insert_x_forwarded_for

    def set_insert_x_forwarded_for(self, value):
        self.insert_x_forwarded_for = value

    def get_server_cloaking(self):
        return self.server_cloaking

    def set_server_cloaking(self, value):
        self.server_cloaking = value

    def get_error_code_update(self):
        return self.error_code_update

    def set_error_code_update(self, value):
        self.error_code_update = value

    def get_url_changes(self):
        return self.url_changes

    def set_url_changes(self, value):
        self.url_changes = value

    def get_url_path_obfuscation(self):
        return self.url_path_obfuscation

    def set_url_path_obfuscation(self, value):
        self.url_path_obfuscation = value

    def get_free_text_replacement(self):
        return self.free_text_replacement

    def set_free_text_replacement(self, value):
        self.free_text_replacement = value

    def get_http_modification_rule_list(self):
        return self.http_modification_rule_list

    def set_http_modification_rule_list(self, value):
        self.http_modification_rule_list = value

    def get_service_always_up(self):
        return self.service_always_up

    def set_service_always_up(self, value):
        self.service_always_up = value

    def get_appshape_plus_script_association(self):
        return self.appshape_plus_script_association

    def set_appshape_plus_script_association(self, value):
        self.appshape_plus_script_association = value

    def get_client_proximity_type(self):
        return self.client_proximity_type

    def set_client_proximity_type(self, value):
        self.client_proximity_type = value

    def get_https_redirect(self):
        return self.https_redirect

    def set_https_redirect(self, value):
        self.https_redirect = value

    def get_connection_handling_on_service_down(self):
        return self.connection_handling_on_service_down

    def set_connection_handling_on_service_down(self, value):
        self.connection_handling_on_service_down = value

    def get_bandwidth_traffic_control(self):
        return self.bandwidth_traffic_control

    def set_bandwidth_traffic_control(self, value):
        self.bandwidth_traffic_control = value

    def get_frontend_tcp_optimization_policy(self):
        return self.frontend_tcp_optimization_policy

    def set_frontend_tcp_optimization_policy(self, value):
        self.frontend_tcp_optimization_policy = value

    def get_backend_tcp_optimization_policy(self):
        return self.backend_tcp_optimization_policy

    def set_backend_tcp_optimization_policy(self, value):
        self.backend_tcp_optimization_policy = value

    def get_bwm_contract_per_string(self):
        return self.bwm_contract_per_string

    def set_bwm_contract_per_string(self, value):
        self.bwm_contract_per_string = value

    def get_script_association(self):
        return self.script_association

    def set_script_association(self, value):
        self.script_association = value

    def get_traffic_contract(self):
        return self.traffic_contract

    def set_traffic_contract(self, value):
        self.traffic_contract = value

    def print_attributes(self):
        attributes = {
            "Service ID": self.service_id,
            "Application": self.application,
            "Service Port": self.service_port,
            "Protocol": self.protocol,
            "Action": self.action,
            "Group ID": self.group_id,
            "Real Server Port": self.real_server_port,
            "Description": self.description,
            "Hostname": self.hostname,
            "Nameserver Groups": self.nameserver_groups,
            "Delayed Binding": self.delayed_binding,
            "Persistency Mode": self.persistency_mode,
            "Persistency Timeout": self.persistency_timeout,
            "Client NAT Mode": self.client_nat_mode,
            "HTTPS Redirect": self.https_redirect,
            "Connection Handling on Service Down": self.connection_handling_on_service_down,
            "Session Timeout": self.session_timeout,
            "Send RST on Connection Close": self.send_rst_on_connection_close,
            "Zero Window Size in SYN-ACK": self.zero_window_size_in_syn_ack,
            "Close Session on Slow Aging": self.close_session_on_slowaging,
            "Close Session on Fast Aging": self.close_session_on_fastaging,
            "Traffic Contract": self.traffic_contract,
            "HTTP Modification Rule List": self.http_modification_rule_list,
            "Script Association": self.script_association,
            "Service Always Up": self.service_always_up,
            "Client Proximity Type": self.client_proximity_type,
            "Bandwidth Traffic Control": self.bandwidth_traffic_control,
            "BWM Contract Per String": self.bwm_contract_per_string,
            "Server Cloaking": self.server_cloaking,
            "Error Code Update": self.error_code_update,
            "URL Changes": self.url_changes,
            "URL Path Obfuscation": self.url_path_obfuscation,
            "Free Text Replacement": self.free_text_replacement,
            "Service Cluster": self.service_cluster,
            "EERT Active Attackers Feed": self.eert_active_attackers_feed,
            "EAAF in CDN Deployment": self.eaaf_in_cdn_deployment,
            "IP Address Header": self.ip_address_header,
            "Sideband Policy ID": self.sideband_policy_id,
            "Logging and Reporting": self.logging_and_reporting,
            "Traffic Event Log Policy": self.traffic_event_log_policy,
            "Counter Based Reporting": self.counter_based_reporting,
            "Granularity Level for DPM": self.granularity_level_for_dpm,
            "Defense Messaging Policy": self.defense_messaging_policy,
            "Satisfied Response Time Threshold": self.satisfied_response_time_threshold,
            "TCP Frontend": self.TCPFrontend,
            "TCP Backend": self.TCPBackend,
            "Redirect String": self.redirect_string,
            "Virtual Associate": self.virt_assoiciate
        }

        for key, value in attributes.items():
            print(f"{key}: {value}")


class TCPProfile:
    def __init__(self,name ,tcp_timestamp="Enable", tcp_keep_alive="Disable", keep_alive_idle=900,
                 keep_alive_count=3, keep_alive_interval=75, enable_tcp_optimization="Enable",
                 policy_id="default", description="default", congestion_control="Hybla+Pacing",
                 congestion_window_scale=0, congestion_decrease=0, rcv_buffer_size="128K",
                 snd_buffer_size="128K", read_buffer_size="64K", connection_closing_aging=0,
                 max_segment_size="Default", selective_ack="Enable", ack_on_push="Enable",
                 adaptive_tuning="Enable", nagle="Disable"):
        self.name = name
        self.tcp_timestamp = tcp_timestamp
        self.tcp_keep_alive = tcp_keep_alive
        self.keep_alive_idle = keep_alive_idle
        self.keep_alive_count = keep_alive_count
        self.keep_alive_interval = keep_alive_interval
        self.enable_tcp_optimization = enable_tcp_optimization
        self.policy_id = policy_id
        self.description = description
        self.congestion_control = congestion_control
        self.congestion_window_scale = congestion_window_scale
        self.congestion_decrease = congestion_decrease
        self.rcv_buffer_size = rcv_buffer_size
        self.snd_buffer_size = snd_buffer_size
        self.read_buffer_size = read_buffer_size
        self.connection_closing_aging = connection_closing_aging
        self.max_segment_size = max_segment_size
        self.selective_ack = selective_ack
        self.ack_on_push = ack_on_push
        self.adaptive_tuning = adaptive_tuning
        self.nagle = nagle

    def get_name(self):
        return self.name

    def set_name(self, value):
        self.name = value

    def get_tcp_timestamp(self):
        return self.tcp_timestamp

    def set_tcp_timestamp(self, value):
        self.tcp_timestamp = value

    def get_tcp_keep_alive(self):
        return self.tcp_keep_alive

    def set_tcp_keep_alive(self, value):
        self.tcp_keep_alive = value

    def get_keep_alive_idle(self):
        return self.keep_alive_idle

    def set_keep_alive_idle(self, value):
        self.keep_alive_idle = value

    def get_keep_alive_count(self):
        return self.keep_alive_count

    def set_keep_alive_count(self, value):
        self.keep_alive_count = value

    def get_keep_alive_interval(self):
        return self.keep_alive_interval

    def set_keep_alive_interval(self, value):
        self.keep_alive_interval = value

    def get_enable_tcp_optimization(self):
        return self.enable_tcp_optimization

    def set_enable_tcp_optimization(self, value):
        self.enable_tcp_optimization = value

    def get_policy_id(self):
        return self.policy_id

    def set_policy_id(self, value):
        self.policy_id = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_congestion_control(self):
        return self.congestion_control

    def set_congestion_control(self, value):
        self.congestion_control = value

    def get_congestion_window_scale(self):
        return self.congestion_window_scale

    def set_congestion_window_scale(self, value):
        self.congestion_window_scale = value

    def get_congestion_decrease(self):
        return self.congestion_decrease

    def set_congestion_decrease(self, value):
        self.congestion_decrease = value

    def get_rcv_buffer_size(self):
        return self.rcv_buffer_size

    def set_rcv_buffer_size(self, value):
        self.rcv_buffer_size = TcpSettings.parse_buffer_size(value)

    def get_snd_buffer_size(self):
        return self.snd_buffer_size

    def set_snd_buffer_size(self, value):
        self.snd_buffer_size = TcpSettings.parse_buffer_size(value)

    def get_read_buffer_size(self):
        return self.read_buffer_size

    def set_read_buffer_size(self, value):
        self.read_buffer_size = TcpSettings.parse_buffer_size(value)

    def get_connection_closing_aging(self):
        return self.connection_closing_aging

    def set_connection_closing_aging(self, value):
        self.connection_closing_aging = value

    def get_max_segment_size(self):
        return self.max_segment_size

    def set_max_segment_size(self, value):
        self.max_segment_size = value

    def get_selective_ack(self):
        return self.selective_ack

    def set_selective_ack(self, value):
        self.selective_ack = value

    def get_ack_on_push(self):
        return self.ack_on_push

    def set_ack_on_push(self, value):
        self.ack_on_push = value

    def get_adaptive_tuning(self):
        return self.adaptive_tuning

    def set_adaptive_tuning(self, value):
        self.adaptive_tuning = value

    def get_nagle(self):
        return self.nagle

    def set_nagle(self, value):
        self.nagle = value
