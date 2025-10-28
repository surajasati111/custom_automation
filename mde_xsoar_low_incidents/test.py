import math
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



url = ""
today_date = datetime.datetime.now().date()

def convert_date(date_):
    #print(str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z')))
    return str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z'))


def generate_token():
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = 'grant_type=client_credentials&client_id= &client_secret= '
    response_ = requests.post('https://auth.proofpoint.com/v1/token', headers=headers, data=data)
    #print(response.json())
    get_response = response_.json()
    return get_response["access_token"]
    #print(get_token)
    

def incident_count(token):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer " + token
    }

    payload = json.dumps({
      "filters": {
        "time_range_filter": {
          "start": "2025-01-21 00:00:00",
          "end": "2025-01-21 02:59:59"
        },
        "source_filters": [
          "tap",
          "abuse_mailbox"
        ],
        "sortParams": [{
            "sort": "desc",
            "colId": "closedAt"
        }],
        #"other_filters":[
        #    "open_incidents"
        #],
      }
    })
    print("payload", payload)

    response_2 = requests.post("https://threatprotection-api.proofpoint.com/api/v1/tric/incidents/count", headers=headers, data=payload)
    print("count=", response_2.json())
    return headers, response_2.json()

    
def incident_data(headers, toatl_inc_number):    
    max_per_req = 500
    total_requests = math.ceil(toatl_inc_number / max_per_req)

    #toatl_inc_number = 400
    req_range = {}

    if toatl_inc_number > max_per_req:
        total_requests = math.floor( toatl_inc_number/ max_per_req)
        print("aa", total_requests)
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
        if int(toatl_inc_number%max_per_req) > 0 :
            req_range[list(req_range.keys())[-1]+max_per_req+for_one] = list(req_range.keys())[-1]+max_per_req + int(toatl_inc_number%max_per_req) - 1 + for_one

    else:
        print("else")
        req_range[0] = toatl_inc_number

    incidents = []

    for start_row, end_row in req_range.items():
        print(start_row, "+++++++" ,end_row)
        payload_2 = json.dumps({
          "filters": {
                "incident_id_filters": [],
                "time_range_filter": {
                  "start": "2025-01-21 00:00:00",
                  "end": "2025-01-21 02:59:59"
                },
                "source_filters": [
                  "tap",
                  "abuse_mailbox"
                ],
                #"other_filters":[
                #    "open_incidents"
                #],
            },
            "endRow": end_row,
            "sortParams": [{
                "sort": "desc",
                "colId": "closedAt"
            }],
            "startRow": start_row
        })

        response_3 = requests.post("https://threatprotection-api.proofpoint.com/api/v1/tric/incidents", headers=headers, data=payload_2)
        test = response_3.json()
        print("dadasdsad", len(test['incidents']))
        final_data = response_3.json()
        # Append incidents to list
        data = final_data.get('incidents', [])
        incidents += data
        
    print("final_count", len(incidents))

    """
    df = pd.read_json(StringIO(json.dumps(incidents)))
    df1 = df.query('assignedTeamName == "ABB SOC"')
    rows, columns = df1.shape

    print(f"Rows: {rows}, Columns: {columns}")

    df1.to_excel("test.xlsx")
    """
    return incidents


def get_xsoar_inc(headers, qry):

    page = 0  # page number ot start at
    size = 2  # number of Incidents to return per page
    from_date = dateutil.relativedelta.relativedelta(days=90)
    to_date = dateutil.relativedelta.relativedelta(days=0)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")

    from_date = convert_date(current_date - from_date)
    to_date = convert_date(current_date - to_date)

    #logging.info(f"from date={from_date} to To Date={to_date}")
    print(f"from date={from_date} to To Date={to_date}")

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
    res = requests.post(f"{url}/incidents/search", headers=headers, json=body, verify=False)
    total = res.json().get('total', 0)
    incident = res.json().get('data', [])
    print("incident",incident)
    return total, incident

# To create xSOAR Incident
def create_xsoar_inc(headers, payload):
    # map the values with the keys
    response = requests.post(f"{url}/incident", json=payload, verify=False, headers=headers)
    inc_details = response.json()
    print(inc_details["id"], "----", inc_details["name"])
    return inc_details["id"]


def close_xsoar_inc(headers, id_):
    if id_:
        print("_id===", id_)
        # will remove once tested
        body = ('{"closeReason":"Resolved","closeNotes":"Based ","id":"' + str(id_) + '"}')
        response = requests.post(f"{url}/incident/close", headers=headers, data=body, verify=False)
        #incident_obj = json.loads(response.content)
        inc_details = response.json()
        logging.info(f"Closing the xSOAR id: {id_}")
        print(inc_details["id"])
        return inc_details["id"]


if __name__ == '__main__':
    get_token = generate_token()
    headers, get_incident_count = incident_count(get_token)
    get_incident_data = incident_data(headers, get_incident_count)
    
    count = 0
    df = pd.read_json(StringIO(json.dumps(get_incident_data)))
    dff = df.query('assignedTeamName == "ABB SOC"')
    rows, columns = dff.shape

    print(f"Rows: {rows}, Columns: {columns}")

    to_be_create_inc = []
    to_be_close_inc = []

    def get_priority(pri):
        if pri == "high":
            priority = 1
        elif pri == "medium":
            priority = 2
        else:
            priority = 3
        return priority    
 
    headers = {
        "Authorization": "",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    #dff.to_excel("test.xlsx")
    for index, row in dff.iterrows():
        print("priority", row["priority"])
        state = "Active" if row['state'] == "open" else "Closed"
        to_be_create_inc.append(
        {
            "name":row['title'], 
            "type": "Proof Point",
            "createInvestigation":True,
            "lastupdatetime":row['updatedAt'],
            "details":f"INC-{row['displayId']}", 
            "CustomFields": {
                "assigneduser":row['assignedUserName'], 
                "externallink": f"https://threatresponse.proofpoint.com/incidents/{row['id']}", 
                "logsource": (row['sourceTypes'])[0], 
                "initialdisposition": (row['dispositions'])[0], 
                "resourceid": row['sid'], 
                "applicationid": f"INC-{row['displayId']}",
                "ticketcloseddate": row.get('closedAt', None),
            },
            "occurred": row['createdAt'],
            "severity": get_priority(row["priority"]), 
            "state": state
        })
        if row['state'] == "closed":
            to_be_close_inc.append({"inc_id":f"'INC-{row['displayId']}", "priority": row['closedAt']})
        count += 1
        #exit()
    print("to_be_create_inc===", len(to_be_create_inc))
    print("to_be_close_inc===", len(to_be_close_inc))
    
    #exit()    
    # check wether incident create or not
    creted_inc, closed_inc = [], []
    for item in to_be_create_inc:
        query = f'details:"{item['details']}"'
        #query = f'type:"Proof Point" and applicationid:"{item['details']}"'
        print(query)
        inc_count, get_incident = get_xsoar_inc(headers, query)
        print(inc_count, get_incident)
        print(item)
        exit()
        if inc_count >= 1:
            print("aaa=====", item["state"])
            if item["state"] == "Closed":
                print("need to close data", get_incident[0]["id"])
                close_xsoar_inc(headers, get_incident[0]["id"])
                closed_inc.append(f"INC-{item['details']}")
            else:
                print("incident is open so ignore", get_incident[0]["id"])
        else:
            print("need to create data")
            create_xsoar_inc(headers, item)
            creted_inc.append(f"INC-{item['details']}")
        #exit()
    print(f"closed_inc count {len(closed_inc)} and closed_inc==={closed_inc}")
    print(f"creted_inc count {len(creted_inc)} and creted_inc==={creted_inc}")