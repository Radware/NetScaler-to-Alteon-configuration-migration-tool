

def is_redirect_http_https_policy(policy_name,responder_policy, responder_action):
    policy_atcion = None
    for policy in responder_policy:
        for action in responder_action:
            if policy["policy_name"] == policy_name:
                if action["policy_action_name"] == policy["policy_action"]:
                    policy_atcion = action["actions"]

    if policy_atcion:
        if "redirect" in policy_atcion.lower() or "respondwit" in policy_atcion.lower():
            if "https" in policy_atcion.lower():
                return True
    else:
        return False



