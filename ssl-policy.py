class SSLPolicy:
    def __init__(self):
        # Backend SSL
        self.backend_ssl_encryption = "Disable"
        self.backend_include_sni = "Disable"
        self.backend_client_certificate = ""
        self.backend_server_authentication_policy = ""
        self.backend_session_reuse = "Inherit"
        self.backend_source_match_reuse = "Enable"
        self.backend_session_ticket = "Disable"
        self.backend_allowed_ssl_protocol_version = ["TLS1.2", "TLS1.3"]
        self.backend_allowed_signature_algorithms = ""
        self.backend_allowed_ssl_groups = ""

        # Frontend SSL
        self.frontend_ssl_encryption = "Enable"
        self.frontend_cipher_suite = "Main"
        self.frontend_intermediate_ca = "None"
        self.frontend_client_authentication_policy = ""
        self.frontend_allowed_ssl_protocol_version = ["TLS1.2", "TLS1.3"]
        self.frontend_allowed_signature_algorithms = ""
        self.frontend_allowed_ssl_groups = ""
        self.frontend_maximum_early_data = ""
        self.frontend_session_reuse = "Inherit"
        self.frontend_session_ticket = "Disable"

    # Getters and Setters for Backend SSL
    def get_backend_ssl_encryption(self):
        return self.backend_ssl_encryption

    def set_backend_ssl_encryption(self, value):
        self.backend_ssl_encryption = value

    def get_backend_include_sni(self):
        return self.backend_include_sni

    def set_backend_include_sni(self, value):
        self.backend_include_sni = value

    def get_backend_client_certificate(self):
        return self.backend_client_certificate

    def set_backend_client_certificate(self, value):
        self.backend_client_certificate = value

    def get_backend_server_authentication_policy(self):
        return self.backend_server_authentication_policy

    def set_backend_server_authentication_policy(self, value):
        self.backend_server_authentication_policy = value

    def get_backend_session_reuse(self):
        return self.backend_session_reuse

    def set_backend_session_reuse(self, value):
        self.backend_session_reuse = value

    def get_backend_source_match_reuse(self):
        return self.backend_source_match_reuse

    def set_backend_source_match_reuse(self, value):
        self.backend_source_match_reuse = value

    def get_backend_session_ticket(self):
        return self.backend_session_ticket

    def set_backend_session_ticket(self, value):
        self.backend_session_ticket = value

    def get_backend_allowed_ssl_protocol_version(self):
        return self.backend_allowed_ssl_protocol_version

    def set_backend_allowed_ssl_protocol_version(self, value):
        self.backend_allowed_ssl_protocol_version = value

    def get_backend_allowed_signature_algorithms(self):
        return self.backend_allowed_signature_algorithms

    def set_backend_allowed_signature_algorithms(self, value):
        self.backend_allowed_signature_algorithms = value

    def get_backend_allowed_ssl_groups(self):
        return self.backend_allowed_ssl_groups

    def set_backend_allowed_ssl_groups(self, value):
        self.backend_allowed_ssl_groups = value

    # Getters and Setters for Frontend SSL
    def get_frontend_ssl_encryption(self):
        return self.frontend_ssl_encryption

    def set_frontend_ssl_encryption(self, value):
        self.frontend_ssl_encryption = value

    def get_frontend_cipher_suite(self):
        return self.frontend_cipher_suite

    def set_frontend_cipher_suite(self, value):
        self.frontend_cipher_suite = value

    def get_frontend_intermediate_ca(self):
        return self.frontend_intermediate_ca

    def set_frontend_intermediate_ca(self, value):
        self.frontend_intermediate_ca = value

    def get_frontend_client_authentication_policy(self):
        return self.frontend_client_authentication_policy

    def set_frontend_client_authentication_policy(self, value):
        self.frontend_client_authentication_policy = value

    def get_frontend_allowed_ssl_protocol_version(self):
        return self.frontend_allowed_ssl_protocol_version

    def set_frontend_allowed_ssl_protocol_version(self, value):
        self.frontend_allowed_ssl_protocol_version = value

    def get_frontend_allowed_signature_algorithms(self):
        return self.frontend_allowed_signature_algorithms

    def set_frontend_allowed_signature_algorithms(self, value):
        self.frontend_allowed_signature_algorithms = value

    def get_frontend_allowed_ssl_groups(self):
        return self.frontend_allowed_ssl_groups

    def set_frontend_allowed_ssl_groups(self, value):
        self.frontend_allowed_ssl_groups = value

    def get_frontend_maximum_early_data(self):
        return self.frontend_maximum_early_data

    def set_frontend_maximum_early_data(self, value):
        self.frontend_maximum_early_data = value

    def get_frontend_session_reuse(self):
        return self.frontend_session_reuse

    def set_frontend_session_reuse(self, value):
        self.frontend_session_reuse = value

    def get_frontend_session_ticket(self):
        return self.frontend_session_ticket

    def set_frontend_session_ticket(self, value):
        self.frontend_session_ticket = value