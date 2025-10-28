import requests
from datetime import datetime, timedelta
import json


# ===== CONFIG =====
tenant_id = ""
client_id = ""
client_secret = ""

now_date_time = datetime.now()

# ===== HELPER FUNCTIONS =====
def convert_date(date_):
    """Format datetime in Microsoft Graph style."""
    return date_.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')


def get_token():
    """Retrieve OAuth2 token from Microsoft Identity Platform."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = {
        'scope': 'https://graph.microsoft.com/.default',
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'client_credentials'
    }
    resp = requests.post(url=url, data=body, verify=False)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_xsoar_inc(qry):
    from_date = datetime.now() - timedelta(hours = 24)
    to_date = datetime.now() - timedelta(hours = 0)
    #print(f"qry={qry} from_date={from_date}, -- to_date={to_date}")
    #exit()
    res = demisto.executeCommand("getIncidents", {
        'query': qry,
        'fromdate': from_date.strftime('%Y-%m-%dT%H:%M:%S.0000000Z'),
        'todate': to_date.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')
    })
    # print(res[0]["Contents"]["data"][0]["id"])
    return res[0]["Contents"]


# To create xSOAR Incident
def create_xsoar_inc(payload):
    print("payload", payload)
    return demisto.executeCommand("createNewIncident", payload)

def get_mde_data(token, type_):
    now_hour_date_time = datetime.now() - timedelta(hours = 0)
    last_hour_date_time = datetime.now() - timedelta(hours = 2)
    headers = {"Authorization": f"Bearer {token}"}

    if type_ == "AAD":
        url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
        params = {
            "$filter": (
                f"createdDateTime ge {last_hour_date_time.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')} and "
                f"createdDateTime lt {now_hour_date_time.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')} and "
                f"serviceSource eq 'azureAdIdentityProtection'"
            )
        }
    else:
    # Microsoft Graph Security API endpoint to get alerts
        url = "https://graph.microsoft.com/beta/security/alerts_v2"
        params = {
            "$filter": (
                f"createdDateTime ge {last_hour_date_time.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')} and "
                f"createdDateTime lt {now_hour_date_time.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')} and "
                f"(serviceSource eq 'microsoft365Defender' or serviceSource eq 'microsoftDefenderForCloudApps')"
            )
        }

    print(params)
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def revoke_user_session(token, user_):
    """Revoke all active sign-in sessions for a user."""
    url = f'https://graph.microsoft.com/v1.0/users/{user_}/revokeSignInSessions'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    if response.status_code == 200:
        print(f"Successfully revoked session for user: {user_}")
    else:
        print(f"Failed to revoke session for {user_}: {response.status_code}, {response.text}")


def alerts_extract(token, alerts):
    """Process alerts, filter external domains, save to CSV."""
    fields = [
        "Alert Id", "Domain (Only Ext)", "Name", "Display Email ID","Incident Id", "Severity", "Status", "Created Date",
        "Fisrt Activity Date", "Script Running Time", "Type"
    ]

    rows = []
    total_count = 0
    sev_dict = {"high": 0, "medium": 0, "low": 0, "informational": 0}

    red_alerts = ["Compromised user account identified through attack activity analysis", "Successful authentication from a Malicious IP", "Account compromised following a password-spray attack", "Activity from a password-spray associated IP address", "Leaked credentials"]
    blue_alerts=["Anonymous IP address", "Anomalous Token", "Password Spray", "Unfamiliar sign-in properties", "Atypical travel", "Malicious sign in from a risky IP address", "Successful authentication from a Suspicious IP", "Suspicious sign in with CSRF speedbump trigger", "Activity from an anonymous proxy", "Activity from a TOR IP address (preview)", "Malicious IP address", "Anonymous proxy activity"]

    define_alerts = red_alerts + blue_alerts
    revoke_user_session_list, servicenow_ticket_user, alerts_title = [], [], []
    user_list = []

    table_data = "<table border='1'> <tr> <th>Alert Id </th> <th>Domain (Only Ext)</th> <th>Name</th> <th>Email</th> <th>User Principal Name</th> <th>Incident Id</th> <th>Severity</th> <th>Status</th> <th>Created Date from MDE</th> <th>First Activity Date</th> <th>Type</th> </tr>"

    for alert in alerts.get('value', []):
        total_count += 1
        evidence_list = alert.get("evidence", [])

        if not evidence_list:
            continue

        user_account = evidence_list[0].get("userAccount", {})
        domain_name = user_account.get("domainName", "")
        display_name = user_account.get("displayName", "")
        user_principal_name = user_account.get("userPrincipalName", "")
        user_id = user_account.get("id")

        if domain_name:
            if domain_name.lower() == "ext.abb.com":
                # Appending all the title in one list
                alerts_title.append(alert.get("title"))

                get_user_details = get_xsoar_inc(f'type:"MDE Guest Users" detecteduser:{user_principal_name}')
                #print(get_user_details)
                # exit()
                if get_user_details["total"] == 0:

                    inc_type = ""
                    sev = alert.get("severity", "").lower()
                    if sev in sev_dict:
                        sev_dict[sev] += 1

                    # Check if alerts are in blue list will append in list will revoke the session only
                    if alert.get("title") in blue_alerts:
                        revoke_user_session_list.append(user_principal_name)
                        inc_type = "Blue"

                    # Check if alerts are in red list will append in list will revoke the session and create service now ticket
                    if alert.get("title") in red_alerts:
                        revoke_user_session_list.append(user_principal_name)
                        servicenow_ticket_user.append(display_name)
                        inc_type = "Red"

                    table_data +=  f'<tr><td>{alert.get("id")}</td><td>{domain_name}</td><td>{alert.get("title")}</td><td>{display_name}</td><td>{user_principal_name}</td><td>{alert.get("incidentId")}</td><td>{alert.get("severity")}</td><td>{alert.get("status")}</td><td>{alert.get("createdDateTime")}</td><td>{alert.get("firstActivityDateTime")}</td><td>{inc_type}</td></tr>'

                    if user_principal_name:
                        revoke_user_session(token, user_principal_name)

        #alerts_title.append("Test: Abnormal User Behavior Pattern Identified (Simulated).")

    # wil get the new rule name which is not there in pre define list
    get_new_rule_list = list(set(alerts_title).difference(define_alerts))

    table_data += "</table>"

    # Sending mail to Team for new alert
    if get_new_rule_list:
        print("need to send an emial...")
        send_email(get_new_rule_list)

    # if alerts found
    if revoke_user_session_list:
        create_xsoar_inc({
                "name": f'Automated Containment Actions Executed on Guest User Accounts (MDE Alerts)',
                "playbook": "MDE Guest User Accounts",
                "createInvestigation": True,
                "detecteduser": list(dict.fromkeys(revoke_user_session_list)),
                "highriskyusers": list(dict.fromkeys(servicenow_ticket_user)),
                "alertcount": len(list(dict.fromkeys(revoke_user_session_list))),
                "severity": 1,
                "state": "New",
                "cmdbuser": table_data,
                "type": "MDE Guest Users"
            })
    else:
        print("No Incident Found.")

    print(
        f"Total Count={total_count}, "
        f"Filtered Count={len(rows)}, "
        f"High Count={sev_dict['high']}, "
        f"Medium Count={sev_dict['medium']}, "
        f"Low Count={sev_dict['low']}, "
        f"Informational Count={sev_dict['informational']}",
        f"New Alerts title Names={get_new_rule_list, set(alerts_title)}",
        f"Need to create snow ticket for user={servicenow_ticket_user}"
    )


def send_email(rule_list):
    final_body = f'''
    Hi Team, <br/><br/>
    A new alert has been observed concerning <b>guest user accounts</b>. <br/><br/>
    Alert Title:
    <ol>'''

    for rule_ in rule_list:
        final_body += f'<li>{rule_}</li>'

    final_body += '''</ol>
    Please review the alert details and determine the appropriate remediation actions. If applicable, add this alert to the <b>automation list</b> to ensure XSOAR handling the incident moving forward. <br/><br/>
    Thanks & Regards,<br/>
    ABB SOAR Team
        '''
    demisto.executeCommand("send-mail", {"to": "glb.dnr.l3@abb.com, DRSME@abb.com, suryaprakash.asti@in.abb.com", "subject": "New MDE Alert Detected for Guest User Accounts – Action Required", "htmlBody": final_body, "using": "GLB_SOAR_Services"})
    demisto.results(False)


# ===== MAIN =====
if __name__ in ('__main__', '__builtin__', 'builtins'):
    print(f"Script started at {datetime.now()}")
    token = get_token()
    alerts_365 = get_mde_data(token, "365")
    aad_identity_protection_alerts  = get_mde_data(token, "AAD")
    # all_alerts = alerts_365 + aad_identity_protection_alerts

    all_alerts = alerts_365.copy()
    all_alerts.update(aad_identity_protection_alerts)

    get_add_alerts = alerts_extract(token, all_alerts)
    print(f"Script End at {datetime.now()}")
