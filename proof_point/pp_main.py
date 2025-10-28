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
requests.packages.urllib3.disable_warnings()

dir_name = os.path.dirname(__file__)
now = datetime.datetime.now().date()
log_path = f'{dir_name}/logs/{now}_incident.log'
logging.basicConfig(filename=log_path, level=logging.INFO)

url = ""
today_date = datetime.datetime.now().date()


def convert_date(date_):
    # print(str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z')))
    return str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z'))


def get_date_range():
    start_date = dateutil.relativedelta.relativedelta(days=3)
    end_date = dateutil.relativedelta.relativedelta(days=0)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")
    return current_date - start_date, current_date - end_date


def generate_token():
    headers_ = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = 'grant_type=client_credentials&client_id= &client_secret= '
    response_ = requests.post('https://auth.proofpoint.com/v1/token', headers=headers_, data=data)
    # print(response.json())
    get_response = response_.json()
    return get_response["access_token"]
    # print(get_token)
    

def incident_count(token, start_date, end_date):
    print(f"{start_date}  +++++++ {end_date}")
    logging.info(f"{start_date}  +++++++ {end_date}")
    headers_ = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }

    # "2025-01-30 00:00:00"
    # "2025-01-30 23:59:59"
    payload = json.dumps({
      "filters": {
        "time_range_filter": {
          "start": str(start_date),
          "end": str(end_date)
        },
        "source_filters": [
          "tap",
          "abuse_mailbox"
        ],
        "sortParams": [{
            "sort": "desc",
            "colId": "createdAt"
        }],
        # "other_filters":[
        #    "open_incidents"
        # ],
      }
    })
    print("payload", payload)
    response_2 = requests.post("https://threatprotection-api.proofpoint.com/api/v1/tric/incidents/count",
                               headers=headers_, data=payload)
    print("count=", response_2.json())
    logging.info(f"count={response_2.json()}")
    return headers_, response_2.json()

    
def incident_data(headers_, total_inc_number, start_date, end_date):
    max_per_req = 500
    # total_inc_number = 400
    req_range = {}

    if total_inc_number > max_per_req:
        total_requests = math.floor(total_inc_number/max_per_req)
        print("Total_Req=", total_requests)
        logging.info(f"Total_Req={total_requests}")
        count = 0
        fixed = 1
        for_one = 0

        for req in range(total_requests):
            if req == 0:
                req_range[count] = count + max_per_req 
            else:
                req_range[count+fixed] = count + max_per_req 
            count += max_per_req
        if total_requests == 1:
            for_one = 1

        # if the incident number is 1000, 1500, 2000, 3000
        if int(total_inc_number % max_per_req) > 0:
            req_range[list(req_range.keys())[-1]+max_per_req+for_one] = list(req_range.keys())[-1]+max_per_req + int(total_inc_number % max_per_req) - 1 + for_one

    else:
        print("else")
        req_range[0] = total_inc_number

    incidents = []
    
    print(f"{start_date}  +++++++ {end_date}")
    logging.info(f"{start_date}  +++++++ {end_date}")

    for start_row, end_row in req_range.items():
        print(start_row, "+++++++", end_row)
        logging.info(f"{start_row}  +++++++ {end_row}")
        payload_2 = json.dumps({
          "filters": {
                "incident_id_filters": [],
                "time_range_filter": {
                  "start": str(start_date),
                  "end": str(end_date)
                },
                "source_filters": [
                  "tap",
                  "abuse_mailbox"
                ],
                # "other_filters":[
                #    "open_incidents"
                # ],
            },
            "endRow": end_row,
            "sortParams": [{
                "sort": "desc",
                "colId": "createdAt"
            }],
            "startRow": start_row
        })

        response_3 = requests.post("https://threatprotection-api.proofpoint.com/api/v1/tric/incidents",
                                   headers=headers_, data=payload_2)
        test = response_3.json()
        print("Total_Count=", len(test['incidents']))
        final_data = response_3.json()
        # Append incidents to list
        data = final_data.get('incidents', [])
        incidents += data
        
    print("Total Incidents count", len(incidents))
    logging.info(f"Total Incidents count={len(incidents)}")

    """
    df = pd.read_json(StringIO(json.dumps(incidents)))
    df1 = df.query('assignedTeamName == "ABB SOC"')
    rows, columns = df1.shape

    print(f"Rows: {rows}, Columns: {columns}")

    df1.to_excel("test.xlsx")
    """
    return incidents


# to get the incident msg
def incident_message(header_, inc_msg_id):
    # incident_message(headers, "54617295-fe55-4504-a160-c2ed5f75894b")
    payload = json.dumps({
          "filters": {
                "incident_id_filters": [],
            },
            "endRow": 200,
            "sortParams": [{
                "sort": "desc",
                "colId": "createdAt"
            }],
            "startRow": 0
    })
    response = requests.post(f"https://threatprotection-api.proofpoint.com/api/v1/tric/incidents/{inc_msg_id}/messages",
                             headers=header_, data=payload)
    get_response = response.json()
    
    # will return the message only of the incident
    if get_response:
        print(get_response["comments"][0]["comment"])
    # print("count=", response.json())
    return header_, response.json()


def get_xsoar_inc(header_, qry):
    page = 0  # page number ot start at
    size = 2  # number of Incidents to return per page
    from_date = dateutil.relativedelta.relativedelta(days=90)
    to_date = dateutil.relativedelta.relativedelta(days=-1)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")

    from_date = convert_date(current_date - from_date)
    to_date = convert_date(current_date - to_date)

    # logging.info(f"from date={from_date} To Date={to_date}")
    print(f"from date={from_date} to To Date={to_date} and {qry}" )
    logging.info(f"from date={from_date} to To Date={to_date} and {qry}" )

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


def close_xsoar_inc(headers_, id_):
    if id_:
        print("_id===", id_)
        # will remove once tested
        body = ('{"closeReason":"Resolved","closeNotes":"Based ","id":"' + str(id_) + '"}')
        response = requests.post(f"{url}/incident/close", headers=headers_, data=body, verify=False)
        # incident_obj = json.loads(response.content)
        inc_details = response.json()
        logging.info(f"Closing the xSOAR id: {id_}")
        print(inc_details["id"])
        return inc_details["id"]


def get_priority(pri):
    if pri == "high":
        priority = 1
    elif pri == "medium":
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


def extract_and_create_data(pp_data):
    count = 0
    import pandas as pd

    to_be_create_inc, to_be_close_inc = [], []
    get_xsoar_header = header_xsoar()
    for index, row in pp_data:
        new_assigned_user = ""
        if "assignedUserName" in row:
            # checks if variable is equal to NaN
            if(pd.isna(row['assignedUserName'])):
                new_assigned_user = "NA"
        
        #print("aaa=",type(row['closedAt']))
        #print("bbb=",row['closedAt'], len(str(row['closedAt'])))
        close_date = "" if len(str(row['closedAt'])) < 4 else row['closedAt']
        disposition = (row['dispositions'])[0] if row['dispositions'] else ""
        print(close_date)

        strippedEmail = ""
        email = re.findall('\S+@\S+',row["title"])
        if email:
            strippedEmail = str(email[0]).replace('[','').replace(']','')
            print("strippedEmail", strippedEmail)
        
        state = "Active" if row['state'] == "open" else "Closed"
        to_be_create_inc.append(
        {
            "name": row['title'],
            "type": "Proof Point",
            "createInvestigation": True,
            "lastupdatetime": row['updatedAt'],
            "details": f"INC-{row['displayId']}",
            "CustomFields": {
                "assigneduser": new_assigned_user,
                "externallink": f"https://threatresponse.proofpoint.com/incidents/{row['id']}", 
                "logsource": (row['sourceTypes'])[0], 
                "initialdisposition": disposition, 
                "resourceid": row['sid'], 
                "applicationid": f"INC-{row['displayId']}",
                "ticketcloseddate": close_date,
                "detecteduser": strippedEmail
            },
            "occurred": row['createdAt'],
            "severity": get_priority(row["priority"]), 
            "state": state
        })
        if row['state'] == "closed":
            to_be_close_inc.append({"inc_id":f"'INC-{row['displayId']}", "priority": row['closedAt']})
        count += 1
        # exit()
    print("to_be_create_inc===", len(to_be_create_inc))
    print("to_be_close_inc===", len(to_be_close_inc))

    logging.info(f"to_be_create_inc count {len(to_be_create_inc)} and to_be_close_inc==={to_be_close_inc}")

    # check weather incident create or not
    created_inc, closed_inc = [], []
    for item in to_be_create_inc:
        # query = f'details:"{item['details']}"'
        query = f'type:"Proof Point" and applicationid:"{item["details"]}"'
        print(query)
        inc_count, get_incident = get_xsoar_inc(get_xsoar_header, query)
        # print("inc_count=",inc_count, "get_incident=", get_incident[0]["id"])
        print("inc_count=", inc_count)
        logging.info(f"inc_count={inc_count}")
        # print(item)
        # exit()
        if inc_count >= 1:
            if item["state"] == "Closed":
                print("need to close data", get_incident[0]["id"])
                close_xsoar_inc(get_xsoar_header, get_incident[0]["id"])
                closed_inc.append(f"INC-{item['details']}")
            else:
                print("incident is open so ignore", get_incident[0]["id"])
        else:
            print("need to create data")
            created_id = create_xsoar_inc(get_xsoar_header, item)
            created_inc.append(f"INC-{item['details']}")
            if item["state"] == "Closed":
                print("created and closing incident data", created_id)
                close_xsoar_inc(get_xsoar_header, created_id)
                closed_inc.append(f"INC-{item['details']}")
        # exit()
    print(f"closed_inc count {len(closed_inc)} and closed_inc==={closed_inc}")
    print(f"created_inc count {len(created_inc)} and created_inc==={created_inc}")

    logging.info(f"closed_inc count {len(closed_inc)} and closed_inc==={closed_inc}")
    logging.info(f"created_inc count {len(created_inc)} and created_inc==={created_inc}")


if __name__ == '__main__':
    logging.info(f"The script was started at {datetime.datetime.now()}")
    from_d, end_d = get_date_range()

    get_token = generate_token()
    headers, get_incident_count = incident_count(get_token, from_d, end_d)
    get_incident_data = incident_data(headers, get_incident_count, from_d, end_d)
    
    df = pd.read_json(StringIO(json.dumps(get_incident_data)))
    dff = df.query('assignedTeamName == "ABB SOC"')
    rows, columns = dff.shape
    print(f"Rows: {rows}, Columns: {columns}")
    logging.info(f"Filtered Rows: {rows}, Columns: {columns}")
    dff.to_excel("test.xlsx")
    extract_and_create_data(dff.iterrows())
    logging.info(f"The script was ended at {datetime.datetime.now()}")
    logging.info("*******************\n \n \n")
    #exit()
    # incident_message(headers, "54617295-fe55-4504-a160-c2ed5f75894b")
