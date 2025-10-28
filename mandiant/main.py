import os
import math
import re
from math import remainder
import requests
import json
import datetime
import dateutil.relativedelta
import pandas as pd
from io import StringIO
import logging
import urllib3
import openpyxl

requests.packages.urllib3.disable_warnings()
url = "https://dev.dark.abb.com/"
dir_name = os.path.dirname(__file__)
today_date = datetime.datetime.now().date()
log_handler = logging.FileHandler(filename=f'{dir_name}/logs/{today_date}_incident.log', encoding='utf-8')
logging.basicConfig(handlers=[log_handler], level=logging.DEBUG)

path = f"{dir_name}/"
valid_users_file = f"{path}valid_users.xlsx"
invalid_users_file = f"{path}invalid_users.xlsx"


def convert_date(date_):
    # print(str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z')))
    return str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z'))


def get_date_range():
    start_date = dateutil.relativedelta.relativedelta(days=10)
    end_date = dateutil.relativedelta.relativedelta(days=0)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")
    return convert_date(current_date - start_date), convert_date(current_date - end_date)


def get_header():
    return {
        "accept": "application/json",
        "x-apikey": ""
    }

    
def alert_data(headers_, start_date, end_date):
    monitor_id = ""
    alert_type = ""
    url_ = f"https://www.virustotal.com/api/v3/dtm/alerts?sort=created_at&&size=25&monitor_id={monitor_id}&since={start_date}&until={end_date}&alert_type={alert_type}"
    print("url_=", url_)
    response = requests.get(url_, headers=headers_)
    raw_data = response.json()
    df = pd.read_json(StringIO(json.dumps(raw_data)))
    rows, columns = df.shape
    print("Total Mandiant Alert count", rows)
    logging.info(f"Total Mandiant Alert count={rows}")
    logging.info(raw_data)

    """
    df = pd.read_json(StringIO(json.dumps(incidents)))
    df1 = df.query('assignedTeamName == "ABB SOC"')
    rows, columns = df1.shape
    print(f"Rows: {rows}, Columns: {columns}")
    df1.to_excel("test.xlsx")
        return incidents
    """
    return raw_data


def get_xsoar_inc(header_, qry):
    page = 0  # page number ot start at
    size = 2  # number of Incidents to return per page
    from_date = dateutil.relativedelta.relativedelta(days=50)
    to_date = dateutil.relativedelta.relativedelta(days=-1)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")

    from_date = convert_date(current_date - from_date)
    to_date = convert_date(current_date - to_date)

    # logging.info(f"from date={from_date} To Date={to_date}")
    print(f"from date={from_date} to To Date={to_date} and {qry}")
    logging.info(f"from date={from_date} to To Date={to_date} and {qry}")

    body = {
        "userFilter": False,
        "filter": {
            "page": page,
            "size": size,
            "query": f"{qry}",
            "fromDate": from_date,
            "toDate": to_date
        }
    }
    # get incident
    res = requests.post(f"{url}/incidents/search", headers=header_, json=body, verify=False)
    total = res.json().get('total', 0)
    incident = res.json().get('data', [])
    print("incident", total)
    logging.info(f"Total Incident{total}")
    return total, incident


# To create xSOAR Incident
def create_xsoar_inc(header_, payload):
    print("payload", payload)
    # map the values with the keys
    response = requests.post(f"{url}/incident", headers=header_, json=payload, verify=False)
    inc_details = response.json()
    print(inc_details["id"], "----", inc_details["name"])
    logging.info(f'{inc_details["id"]}---- {inc_details["name"]}')
    return inc_details["id"]


def get_priority(pri):
    if pri in "high":
        priority = 1
    elif pri in "medium":
        priority = 2
    else:
        priority = 3
    return priority


def header_xsoar():
    return {
        "Authorization": "",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def get_file_obj(file_):
    wb = openpyxl.load_workbook(filename=file_)
    sheet = wb['Sheet']
    return wb, sheet


def extract_and_create_data(raw_data):
    # print(f'{incident["meets_password_policy"]}, {incident["doc"]["service_account"]["login"]},
    # {incident["severity"]}, {incident["alert_type"]}, {incident["created_at"]}')
    incident_count_to_be_create, incident_count_to_be_add_in_list = 0, 0
    to_be_create_inc, to_be_update_list = [], []
    print("Extracting the data...")
    logging.info("Extracting the data...")
    for incident in raw_data["alerts"]:
        new_dict = {
            "name": f'DTM-Compromised_Credentials - {incident["doc"]["service_account"]["login"]}',
            "domainname": incident["doc"]["service_account"]["profile"]["contact"]["email_domain"],
            "type": "DTM-Credential Leak",
            "accountname": incident["doc"]["service_account"]["service"]["name"],
            "playbook": "DTM Credentials Leak",
            "createInvestigation": True,
            "alerturl": f'https://advantage.mandiant.com/dtm/alerts/{incident["id"]}',
            "alertname": incident["title"],
            "alertid": incident["id"],
            "detecteduser": incident["doc"]["service_account"]["login"],
            "occured": incident["doc"]["timestamp"],
            "CustomFields": {
                "Password_Valid_Invalid": "Valid" if incident["meets_password_policy"] in "true" else "In Valid",
                "alerttype": incident["alert_type"],
                "accounturl": incident["doc"]["service_account"]["service"]["inet_location"]["domain"],
                "sourceurl": incident["doc"]["source_url"],
                'alertid': incident["id"], 
                "affectedusers": incident["doc"]["service_account"]["login"],
            },
            "occurred": incident["doc"]['ingested'],
            "severity": get_priority(incident["severity"]),
            "severity_str": incident["severity"],
            "state": "Active",
        }
        if incident['meets_password_policy'] in "true":
            print(f'need to create incident for use: {incident["doc"]["service_account"]["login"]}')
            logging.info(f'need to create incident for use: {incident["doc"]["service_account"]["login"]}')
            to_be_create_inc.append(new_dict)
            incident_count_to_be_create += 1
        else:
            print(f'need to add in the list for use: {incident["doc"]["service_account"]["login"]}')
            logging.info(f'need to add in the list for use: {incident["doc"]["service_account"]["login"]}')
            to_be_update_list.append(new_dict)
            incident_count_to_be_add_in_list += 1
            # need to be xsoar list
        # exit()
    print("to_be_create_inc===", len(to_be_create_inc))
    print("to_be_update_list===", len(to_be_update_list))
    # logging.info(f"to_be_create_inc count {len(to_be_create_inc)} and to_be_close_inc==={to_be_close_inc}")

    # check weather incident create or not
    created_inc, not_created_inc = 0, 0
    wb_, sheet_ = get_file_obj(valid_users_file)
    for item in to_be_create_inc:
        query = f'alertid:"{item["alertid"]}"'
        inc_count, get_incident = get_xsoar_inc(header_xsoar(), query)
        #inc_count = 0
        print(f"inc_count={inc_count}")
        logging.info(f"inc_count={inc_count}")
        # print(item)
        # exit()
        if inc_count >= 1:
            print("incident is already created", item["name"])
            logging.info(f'incident is already created{item["name"]}')
        else:
            print("need to create data .....")
            created_id = create_xsoar_inc(header_xsoar(), item)
            created_inc += 1
            # Save the data in sheet
            new_row_ = [item["name"], item["domainname"], item["accountname"], item["alerturl"], item["alertname"],
                        item["alertid"], item["detecteduser"], item["occured"], item["severity_str"],
                        item["CustomFields"]["Password_Valid_Invalid"], item["CustomFields"]["alerttype"],
                        item["CustomFields"]["accounturl"], item["CustomFields"]["sourceurl"],
                        item["CustomFields"]["affectedusers"], item["occurred"], datetime.datetime.now()]
            sheet_.append(new_row_)
    wb_.save(valid_users_file)
    # exit()
    print("created_inc_count=", created_inc)
    logging.info(f"created_inc_count={created_inc}")

    # update the list
    no_invalid_count = 0
    wb, sheet = get_file_obj(invalid_users_file)
    for item in to_be_update_list:
        print("need to create data for user", item["CustomFields"].get("affectedusers"))
        no_invalid_count += 1
        # Save the data in sheet
        new_row = [item["name"], item["domainname"], item["accountname"], item["alerturl"], item["alertname"],
                        item["alertid"], item["detecteduser"], item["occured"], item["severity_str"],
                        item["CustomFields"]["Password_Valid_Invalid"], item["CustomFields"]["alerttype"],
                        item["CustomFields"]["accounturl"], item["CustomFields"]["sourceurl"],
                        item["CustomFields"]["affectedusers"], item["occurred"], datetime.datetime.now()]
        sheet.append(new_row)
    wb.save(invalid_users_file)
    print("no_invalid_count=", no_invalid_count)
    logging.info(f"no_invalid_count={no_invalid_count}")


if __name__ == '__main__':
    logging.info(f"The script was started at {datetime.datetime.now()}")
    from_d, end_d = get_date_range()
    get_alert_data = alert_data(get_header(), from_d, end_d)
    extract_and_create_data(get_alert_data)
    logging.info(f"The script was ended at {datetime.datetime.now()}")
    logging.info("*******************\n \n \n")
