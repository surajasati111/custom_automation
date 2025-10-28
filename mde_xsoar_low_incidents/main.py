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


def alert_scan(machine_id, token):
    print(f"Initiate a full antivirus scan on the device and device id= {machine_id}")
    logging.info(f"Initiate a full antivirus scan on the device and device id= {machine_id}")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }
    # 'assignedTo': 'in-wp-sa1@abb.com',
    payload = {"Comment": "scaning", "ScanType": "Full"}
    url = f"https://api.security.microsoft.com/api/machines/{machine_id}/runAntiVirusScan"
    response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)
    # output = json.loads(response.text)
    # print("response=", response.text)
    logging.info(f"Result for the initiated machine= {response.text}")
    return response.text


def request_data(token_):
    start_date = dateutil.relativedelta.relativedelta(days=5)
    end_date = dateutil.relativedelta.relativedelta(days=-1)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")

    print("https://api.securitycenter.microsoft.com/api/alerts?$filter="
          "alertCreationTime gt " + convert_date(current_date - start_date) +
          " and alertCreationTime lt " + convert_date(current_date - end_date))
    # filtering data for date range and status wise
    return get_query("https://api.securitycenter.microsoft.com/api/alerts?$filter="
                     "alertCreationTime gt " + convert_date(current_date - start_date) +
                     " and alertCreationTime lt " + convert_date(current_date - end_date), token_)


def get_mde_data():
    alert_token = get_token(uri="https://api.securitycenter.windows.com")
    response = request_data(alert_token)

    fields = ['Incident Id', 'Alert Id', 'Alert Name', 'Creation Time', 'Status', 'Severity', "Category",
              "Detection Source", "Investigation State", "Machine Id", "Current Date"]
    rows, get_incidents_to_close = [], []

    # name of csv file
    filename_csv = "C:/Users/INSUAST/Downloads/automation/mde_xsoar_low_incidents/low_incident_details.csv"
    total_count, total_low_count, low_count = 0, 0, 0
    #ds_list = ["OfficeATP", "WindowsDefenderAv", "DLP"]
    #and item_["detectionSource"] in ds_list 
    #category_list = ["Exfiltration", "Impact", "Ransomware"]

    for item_ in response["value"]:
        if item_["status"] != "Resolved":
            total_count = total_count + 1
            if item_["severity"] in ["Low"]:
                total_low_count = total_low_count + 1
                
            if item_["severity"] in ["Low"]:

                low_count = low_count + 1
                get_incidents_to_close.append(item_["incidentId"])

                # Initiate scan the device
                alert_scan(item_["machineId"], alert_token)
                
                rows.append([item_["incidentId"], item_["id"], item_["title"], item_["lastUpdateTime"], item_["status"], item_["severity"], item_["category"], item_["detectionSource"], item_["investigationState"], item_["machineId"], today_date])

    logging.info(f"MDE Total Count={total_count}, total_low_count= {total_low_count} , Low Count to be close={low_count}")
    print(f"MDE Total Count={total_count}, total_low_count= {total_low_count}, Filtered Low Count={low_count}")
    logging.info(f"Duplicate MDE incidents needs to be closed={get_incidents_to_close}")
    get_incidents_to_close = list(dict.fromkeys(get_incidents_to_close))
    logging.info(f"Distinct MDE incidents need to be closed={get_incidents_to_close}")
    print(f"Distinct MDE incidents need to be closed={get_incidents_to_close}")

    with open(filename_csv, 'a', encoding="utf-8", newline='') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)
        # writing the fields
        #csvwriter.writerow(fields) # need to be delete from 2nd time
        # writing the data rows
        csvwriter.writerows(rows)
    return get_incidents_to_close


def get_xsoar_data():
    url_ = ''  # Global variable for managing the instance URL
    apikey = ''  # key for prod

    # server url for the API call
    url = f"{url_}/incidents/search"

    page = 0  # page number ot start at
    size = 1500  # number of Incidents to return per page
    curcuitbreaker = 5

    from_date = dateutil.relativedelta.relativedelta(days=365)
    to_date = dateutil.relativedelta.relativedelta(days=-1)
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
    
    query = 'type:"Microsoft 365 Defender ALL Incidents - Low" and status:Active'  #XSOAR UI (e.g status:closed -category:job)
    logging.info(f"query= {query}")
    body = {
        "userFilter": False,
        "filter": {
            "page": page,
            "size": size,
            "query": f"{query}",
            "fromDate": from_date,
            "toDate": to_date
        }
    }

    # get incidents
    res = requests.post(f"{url}", headers=headers, json=body, verify=False)
    total = res.json().get('total', 0)
    incidents = res.json().get('data', [])
    count = 1
    
    # if there are more events than the default size, page through and get them all
    while len(incidents) < total:
        body['filter']['page'] = count
        res = requests.post(f"{url}", headers=headers, json=body, verify=False)
        incidents.extend(res.json().get('data', []))
        count += 1
        # break if this goes crazy
        if count == curcuitbreaker:
            break

    print(f"Incidents Found: {len(incidents)}")
    print(f"Total Incidents: {total}")
    print(f"Number of API calls made: {count}")
    
    logging.info(f"Incidents Found: {len(incidents)} , Total Incidents: {total}, Number of API calls made: {count} ")
    
    return incidents


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
               'comment': "Based on the low-severity alert identified, an antivirus (AV) scan was initiated on the "
                          "corresponding system to verify the presence of any potential threats or malicious activity. "
                          "After completing the scan, if no actionable threats were detected, the alert is reviewed "
                          "and  no further action is required . However, if the AV scan detects any malicious activity "
                          "or threats, a new medium-severity alert will be automatically triggered. This new alert will"
                          "be handled as part of the standard Business-As-Usual (BAU) process for further "
                          "investigation.",
               "status": "Resolved"}
    url = "https://api.security.microsoft.com/api/incidents/" + str(incident_id)
    logging.info(f"Update incident url={url}")
    #response = []
    response = requests.patch(url=url, headers=headers, data=json.dumps(payload), verify=False)
    # output = json.loads(response.text)
    #print("response=", response)
    logging.info(f"Response ={response}")
    return response.text


def incident_close_xsoar(inc_ids):
    if inc_ids:
        
        data = {
            "ids": inc_ids, #["1","2","3"]
            "CustomFields" : {},
            "all" : False,
            "closeReason":"Resolved",
            "closeNotes":"Based on the low-severity alert identified, an antivirus (AV) scan was initiated on the corresponding system to verify the presence of any potential threats or malicious activity. After completing the scan, if no actionable threats were detected, the alert is reviewed and  no further action is required. However, if the AV scan detects any malicious activity or threats, a new medium-severity alert will be automatically triggered. This new alert will be handled as part of the standard Business-As-Usual (BAU) process for further investigation.",
            "data" : {},
            "filter": {}
        }
        
        # if match found close the incident in xsoar
        url = ""
        apikey = ''  # key for prod

        headers = {
            'Content-Type': 'application/json',
            'Authorization': apikey
        }
        
        # body = '{"Owner":"surya.asati@in.abb.com","closeNotes":"Resolved by REST API", "id:178093 or id:178092"}'
        response = requests.post(url, headers=headers, json=data, verify=False)
        incidents_resp_obj = json.loads(response.content)
        logging.info(f"Closing the xSOAR id: {inc_ids}")
        print(f"Closing the xSOAR id: {inc_ids}")
        #print(incidents_resp_obj)


if __name__ == '__main__':
    logging.info("*************************")
    logging.info(f"Script started at {now_date_time}")
    
    # getting the MDE alert
    get_mde_ids = get_mde_data()

    incident_token = get_token(uri="https://api.security.microsoft.com")
    # closing the MDE incidents
    for mde_id in get_mde_ids:
        print(mde_id)
        incident_close_mde(mde_id, incident_token)

    if len(get_mde_ids) > 0:

        # getting the xsoar IDs
        get_result = get_xsoar_data()
        logging.info(f"xSOAR Incident data: {len(get_result)}")
        
        low_inc_dict = {}
        for item in get_result:
            low_inc_dict[item["name"]] = item["id"]

        xsoar_inc_to_be_close = []
        for mde_id in get_mde_ids:
            if f"Microsoft 365 Defender {mde_id}" in low_inc_dict:
                #print(low_inc_dict[f"Microsoft 365 Defender {mde_id}"])
                xsoar_inc_to_be_close.append(low_inc_dict[f"Microsoft 365 Defender {mde_id}"])

        logging.info(f"xsoar_inc_to_be_close {xsoar_inc_to_be_close}")
        print(f"xsoar_inc_to_be_close {len(xsoar_inc_to_be_close)}")
        
        # closing the xsoar incidents
        if len(get_mde_ids) >= len(xsoar_inc_to_be_close):
                incident_close_xsoar(xsoar_inc_to_be_close)       

    logging.info(f"Script ended at {datetime.datetime.now()}")