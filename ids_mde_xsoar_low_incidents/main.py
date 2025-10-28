import requests
import datetime
import pandas as pd
from io import StringIO
import dateutil.relativedelta
import json
import urllib3
import logging
import os
import openpyxl
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dir_name = os.path.dirname(__file__)
path = f"{dir_name}/"
today_date = datetime.datetime.now().date()
now_date_time = datetime.datetime.now()

log_path = f'{dir_name}/logs/{today_date}_low_incident.log'
logging.basicConfig(filename=log_path,
                    level=logging.DEBUG,
                    format='%(asctime)s:%(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%b-%y %H:%M:%S')


def convert_date(date_):
    return str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z'))


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
    return json_response["access_token"]


def get_query(get_data_url, token):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }
    response_ = requests.get(url=get_data_url, headers=headers, verify=False)
    return response_.json()


def query_result(query_):
    url_ = ''  # Global variable for managing the instance URL
    apikey = ''  # key for prod

    # server url for the API call
    url = f"{url_}/incidents/search"

    page = 0  # page number ot start at
    size = 500  # number of Incidents to return per page

    from_date = dateutil.relativedelta.relativedelta(days=365)
    to_date = dateutil.relativedelta.relativedelta(days=0)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")

    from_date = convert_date(current_date - from_date)
    to_date = convert_date(current_date - to_date)

    logging.info(f"from date={from_date} to To Date={to_date}")
    print(f"from date={from_date} to To Date={to_date}")

    # headers for request
    headers = {
        "Authorization": apikey,
        "accept": "application/json",
        "content-type": "application/json"
    }
    
    query = '(type:"Microsoft 365 Defender ALL Incidents - Low" and status:Active) And name:'
    logging.info(f"query_ : {query}{query_}")
    body = {
        "userFilter": False,
        "filter": {
            "page": page,
            "size": size,
            "query": f"{query}{query_}",
            "fromDate": from_date,
            "toDate": to_date
        }
    }

    # get incidents
    res = requests.post(f"{url}", headers=headers, json=body, verify=False)
    incidents = res.json().get('data', [])
    #for item in incidents:
    #    print("dadas=",item["id"],"---", item["name"])
    print(f"Incidents Found: {len(incidents)}")
    logging.info(f"Incidents Found: {len(incidents)}")
    return incidents


def get_xsoar_data(query_):

    complete_data = []
    final_dict = {}
    query_result_data = query_result(query_)

    for data in query_result_data:
        final_dict[data["name"]] = data["id"]

    print(len(final_dict))

    logging.info(f"xSOAR Incident data: {complete_data}")
    logging.info(f"Completed xSOAR Incident data: {final_dict}")

    return final_dict


def incident_close_mde(incident_id, token):
    print(f"Closing the MDE Incident {incident_id}")
    logging.info(f"Closing the MDE Incident {incident_id}")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }
    # 'assignedTo': 'in-wp-sa1@abb.com',
    payload = {"classification": "FalsePositive", "determination": "NotMalicious", 'assignedTo': 'in-wp-sa1@abb.com',
               'comment': "We have completed a review of a total of 546 alerts within XSOAR and MDE. The alerts related to XSOAR which are from calendar year 2024 and carry a 'Low' severity rating. These alerts do not have any associated Microsoft Defender for Endpoint (MDE) alerts, as those were previously reviewed and closed in accordance with the approved process on 13th February 2025. \n \n Additionally, the alerts show no linked devices, nor do they exhibit any active or suspicious behavior. Based on our investigation and these alerts requires no further investigation because of below reasons \n 1. The incidents contain the Service account which is handled by Cloud VM \n 2. Incident Telemetry is not available in KQL because of retention period \n 3. Incident might be closed on MDE but remains open in xsoar. \n We are proceeding with bulk closure of these alerts in Microsoft Defender for Cloud and Microsoft Defender for Servers and 2024 XSOAR Alert. \n The closure will also be reflected in XSOAR to ensure alignment and consistency across all platforms. \n In the event any new evidence or activity emerges indicating a potential threat, the relevant alerts can be re-opened and subjected to further investigation as necessary.", "status": "Resolved"}
    url = "https://api.security.microsoft.com/api/incidents/" + str(incident_id)
    logging.info(f"Update incident url={url}")
    response = requests.patch(url=url, headers=headers, data=json.dumps(payload), verify=False)
    # output = json.loads(response.text)
    #print("response=", response)
    logging.info(f"Response ={response}")
    return response.text


def incident_close_xsoar(inc_id):
    if inc_id:
        # if match found close the incident in xsoar
        url = "/incident/close"
        apikey = ''  # key for prod

        headers = {
            'Content-Type': 'application/json',
            'Authorization': apikey
        }

        # will remove once tested
        body = ('{"closeReason":"Resolved","closeNotes":"The alerts related to XSOAR are from the calendar year 2024/and the last old alert was observed to be jan 2025 and carry a "Low" severity rating. These alerts do not have any associated Microsoft Defender for Endpoint (MDE) alerts, as those were previously reviewed and closed in accordance with the approved process on 13th February 2025.'
                'Additionally, the alerts show no linked devices, nor do they exhibit any active or suspicious behavior. Based on our investigation, these alerts require no further investigation because of the following reasons:'
                'Incident telemetry is not available in KQL because of the retention period.'
                'Incidents might be closed on MDE but remain open in XSOAR.'
                'We are proceeding with the bulk closure of these alerts in XSOAR, and the count ID is 7402.'
                'In the event any new evidence or activity emerges indicating a potential threat, the relevant alerts can be re-opened and subjected to further investigation as necessary.",'
                '"id":"')+str(inc_id)+'"}'
        # body = '{"Owner":"surya.asati@in.abb.com","closeNotes":"Resolved by REST API", "id:178093 or id:178092"}'
        response = requests.post(url, headers=headers, data=body, verify=False)
        incidents_resp_obj = json.loads(response.content)
        logging.info(f"Closing the xSOAR id: {inc_id}")
        print(f"Closing the xSOAR id: {inc_id}")
        #print(incidents_resp_obj)


if __name__ == '__main__':
    logging.info("*************************")
    logging.info(f"Script started at {now_date_time}")
    
    # getting the MDE alert

    get_mde_ids = []

    incident_token = get_token(uri="https://api.security.microsoft.com")
    # closing the MDE incidents
    for mde_id in get_mde_ids:
        #print(mde_id)
        incident_close_mde(mde_id, incident_token)

    # getting the xsoar IDs
    final_list = []
    inc_count = 1
    req_count = 0
    total_per_req = 7
    qry = ""
    for item in get_mde_ids:
        qry += f'Microsoft 365 Defender {item} or '
        if inc_count% total_per_req == 0:
            final_list.append(qry[:-4])
            qry = ""
            req_count += total_per_req
        inc_count += 1

    get_xsoar_ids = []
    for qry_ in final_list:
        # passing query and get the data from xsoar
        get_xsoar_ids.append(get_xsoar_data(qry_))
    #print("aa", get_xsoar_ids)
    
    xsoar_inc_to_be_close = []
    for xsoar_item in get_xsoar_ids:
        #print(xsoar_item)
        for key, val in xsoar_item.items():
            xsoar_inc_to_be_close.append(val)
    
    print(xsoar_inc_to_be_close)
    logging.info(f"xsoar_inc_to_be_close {xsoar_inc_to_be_close}")
    
    # closing the xsoar incidents
    if len(get_mde_ids) >= len(xsoar_inc_to_be_close):
        for inc_id in xsoar_inc_to_be_close:
            incident_close_xsoar(inc_id)       

    logging.info(f"Script ended at {datetime.datetime.now()}")