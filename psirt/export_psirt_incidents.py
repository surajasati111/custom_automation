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

log_path = f'{dir_name}/logs/{today_date}_psirt_incident.log'
logging.basicConfig(filename=log_path,
                    level=logging.DEBUG,
                    format='%(asctime)s:%(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%b-%y %H:%M:%S')


def convert_date(date_):
    return str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z'))


def get_token(uri):
    tenant_id = "372ee9e0-9ce0-4033-a64a-c07073a91ecd"
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



def get_xsoar_data():
    url_ = ''  # Global variable for managing the instance URL
    apikey = ''  # key for prod

    # server url for the API call
    url = f"{url_}/incidents/search"

    page = 0  # page number ot start at
    size = 50  # number of Incidents to return per page
    curcuitbreaker = 5

    from_date = dateutil.relativedelta.relativedelta(days=1)
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
    
    query = 'type:"PSIRT Rule" and status:Active'  #XSOAR UI (e.g status:closed -category:job)
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
    
    

def mail_send():
    import win32com.client as win32
    outlook = win32.Dispatch('outlook.application')
    mail = outlook.CreateItem(0)
    mail.To = "harmeet.singh@in.abb.com;suryaprakash.asti@in.abb.com;arun.kumarrai@in.abb.com"
    mail.Subject = 'Cortex XSOAR Report Incidents Report'
    mail.Body = 'Check out the attached Report..'
    mail.HTMLBody = '<h2>Check out the attached Report.</h2>' #this field is optional
    # To attach a file to the email (optional):
    attachment  = f"{path}incidents_details.csv"
    mail.Attachments.Add(attachment)
    mail.Send()   


if __name__ == '__main__':
    logging.info("*************************")
    logging.info(f"Script started at {now_date_time}")
    complete_data = get_xsoar_data()
    
    if complete_data:
        #fields = ["incidentId", "Name", "Incident Creating", "category", "status"] 
                # writing to csv file  
        with open(f"{path}psirt_incidents_details.csv", 'w', newline='', encoding="utf-8") as csvfile:  
            fieldnames = ["id", "name", "status", "occurred"]
            csvwriter = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            csvwriter.writeheader()
            csvwriter.writerows(complete_data)
    
    #mail_send()
    logging.info(f"Script ended at {datetime.datetime.now()}")