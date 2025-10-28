import requests
import json


def get_token(uri):
    tenant_id = ""
    url = f"https://login.windows.net/{tenant_id}/oauth2/token"
    body = {
        'resource': uri,
        'client_id': "",
        'client_secret': "",
        'grant_type': 'client_credentials'
    }
    req = requests.get(url=url, data=body, verify=False)
    json_response = json.loads(req.text)
    # print(json_response)
    # exit()
    return json_response["access_token"]


def get_query(get_data_url, token):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }
    response_ = requests.get(url=get_data_url, headers=headers, verify=False)
    # print(response_.json())
    return response_.json()


def machine_scan(machine_id, token):
    print(f"Initiate a full antivirus scan on the machine/device id= {machine_id}")
    headers_ = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }
    payload_ = {"Comment": "scaning", "ScanType": "Full"}
    url = f"https://api.security.microsoft.com/api/machines/{machine_id}/runAntiVirusScan"
    response = requests.post(url=url, headers=headers_, data=json.dumps(payload_), verify=False)
    return response.text




if __name__ in ('__main__', '__builtin__', 'builtins'):
    args = demisto.args()
    inc_id = args.get('mde_incident_id')
    print("inc_id=", inc_id)

    # Get token for incident
    incident_token = get_token(uri="https://api.security.microsoft.com")

    # Get Token for alter
    alert_token = get_token(uri="https://api.securitycenter.windows.com")

    result_response = get_query(f"https://api.security.microsoft.com/api/incidents/{inc_id}",incident_token)
    #print(result_response)

    new_machine_list = []
    new_device_list = []

    if result_response["status"] == "Resolved":
        print("Incident is closed, no action required.")
    else:
        for item in result_response["alerts"]:
            #print(item["status"])
            #print(item["devices"])
            #print("\n \n \n \n \n")

            if item["devices"]:
                if item["devices"][0]["deviceDnsName"] not in new_machine_list and item["devices"][0]["deviceDnsName"]:
                    #print("deviceDnsName==", item["devices"][0]["deviceDnsName"] )
                    #print("deviceDnsName==", item["devices"][0]["mdatpDeviceId"] )
                    new_machine_list.append(item["devices"][0]["deviceDnsName"])
                    new_device_list.append(item["devices"][0]["mdatpDeviceId"])
                    # initiating the full AV scan
                    machine_scan(item["devices"][0]["mdatpDeviceId"], alert_token)

        print(f"Initiated AV scan Count ={len(new_device_list)}, Initiated AV scan list ={new_device_list}, AV scaned Device Names = {new_machine_list}")

