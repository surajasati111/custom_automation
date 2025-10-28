from typing import Dict, Any
import requests
import json
import datetime
import dateutil.relativedelta

today_date = datetime.datetime.now().date()


def convert_date(date_):
    return str(date_.strftime('%Y-%m-%dT' + '00:00:00.0000000Z'))


def convert_date2(date_):
    return str(date_.strftime('%Y-%m-%d'))


def get_date_range():
    start_date = dateutil.relativedelta.relativedelta(days=1)
    end_date = dateutil.relativedelta.relativedelta(days=1)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")
    return convert_date2(current_date - start_date), convert_date2(current_date - end_date)


def get_header():
    return {
        "accept": "application/json",
        "x-apikey": "",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }


def alert_data(headers_, start_date, end_date):
    monitor_id = ""
    alert_type = ""
    url_ = f"https://www.virustotal.com/api/v3/dtm/alerts?sort=created_at&&size=25&monitor_id={monitor_id}&since={start_date}T00:00:00.0000000Z&until={end_date}T23:59:59.9999999Z&alert_type={alert_type}"
    print("Requested url_=", url_)
    response = requests.get(url_, headers=headers_)
    raw_data = response.json()
    print("Total mandiant Alert count", len(raw_data["alerts"]))
    return raw_data


def get_xsoar_inc(qry):
    from_date = dateutil.relativedelta.relativedelta(days=7)
    to_date = dateutil.relativedelta.relativedelta(days=-1)
    current_date = datetime.datetime.strptime(str(today_date), "%Y-%m-%d")

    from_date = convert_date(current_date - from_date)
    to_date = convert_date(current_date - to_date)
    print(qry)
    res = demisto.executeCommand("getIncidents", {
        'query': qry,
        'fromdate': from_date,
        'todate': to_date
    })

    # res = demisto.executeCommand("getIncidents", {
    #    'query': qry
    # })

    # print(res[0]["Contents"]["data"][0]["id"])
    return res[0]["Contents"]


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


# To create xSOAR Incident
def create_xsoar_inc(payload):
    print("payload", payload)
    # map the values with the keys
    return demisto.executeCommand("createNewIncident", payload)
    print(new_inc)
    return_results(new_inc)


# To extract mandiant data
def extract_data(raw_data):
    print("Extracting the data...")
    #print(raw_data)
    #exit()
    list_of_users_dict = []
    for inc in raw_data["alerts"]:
        alert_dict = {
            "name": f'Allegedly leak credentials - {inc["doc"]["service_account"]["login"]}',
            "domainname": inc["doc"]["service_account"]["profile"]["contact"]["email_domain"],
            "type": "DTM-Credential Leak",
            "accountname": inc["doc"]["service_account"]["service"]["name"],
            "playbook": "DTM Credentials Leak",
            "createInvestigation": True,
            "alerturl": f'https://advantage.mandiant.com/dtm/alerts/{inc["id"]}',
            "alertname": inc["title"],
            "alertid": inc["id"],
            "detecteduser": inc["doc"]["service_account"]["login"],
            "occured": inc["doc"]["timestamp"],
            "passwordvalidinvalid": "Valid" if inc["meets_password_policy"] in "true" else "In Valid",
            "alerttype": inc["alert_type"],
            "accounturl": inc["doc"]["service_account"]["service"]["inet_location"]["domain"],
            "sourceurl": inc["doc"]["source_url"],
            "affectedusers": inc["doc"]["service_account"]["login"],
            "occurred": inc["doc"]['ingested'],
            "severity": get_priority(inc["severity"]),
            "severity_2": inc["severity"],
            "state": "New",
            "meets_password_policy": inc['meets_password_policy'],
            "threatname":inc.get("doc").get("source_threat").get("name") if inc.get("doc").get("source_threat") is not None else ""
        }
        list_of_users_dict.append(alert_dict)
    return list_of_users_dict


def remove_duplicate(all_):
    updated_list = []
    unique_keys = set()
    count = 0

    for item in all_:
        # Use a composite key to differentiate unique alerts:
        key = (item["affectedusers"], item["passwordvalidinvalid"])

        if key not in unique_keys:
            unique_keys.add(key)
            updated_list.append(item)
        else:
            # Find existing item with same key
            idx = next(i for i, d in enumerate(updated_list) if (d["affectedusers"], d["passwordvalidinvalid"]) == key)
            # Append accounturl if not present
            existing_urls = updated_list[idx]["accounturl"].split(", ")
            if item["accounturl"] not in existing_urls:
                updated_list[idx]["accounturl"] += ", " + item["accounturl"]
        count += 1
    print(f"Toatl Alert={count}, Unique Alert={len(updated_list)}, Duplicate Alert={count - len(updated_list)}")
    return updated_list


def make_dict(incident, inc_type, inc_number):
    return {
            "Timestamp": incident["occurred"],
            "PasswordValidInvalid": inc_type,
            "XSOAR ID": inc_number,
            "Username": incident["affectedusers"],
            "AccountURL": incident["accounturl"],
            "Alert Link": f'https://advantage.mandiant.com/dtm/alerts/{incident["alertid"]}',
            "Alert ID": incident["alertid"],
            "Alert Type": incident["alerttype"],
            "Alert Severity": incident["severity_2"],
            "Monitor Name": "ABB Compromised Credentials_Catch All",
            "Source URL": incident["sourceurl"],
            "Service Account Contact Email Domain": incident["accounturl"],
            "Service Account Name": incident["accountname"],
            "Source Threat Name": incident["threatname"],
            "Xsoar ID Creation Date": f"{(datetime.datetime.now()).strftime('%Y-%m-%dT%H:%M:%S')}"
        }



def create_incidents(incidents):
    incident_count_to_be_create, incident_count_to_be_add_in_list, incident_count_to_be_updated = 0, 0, 0
    to_be_create_inc, to_be_update_inc, to_be_update_list = [], [], []
    for incident in incidents:
        if incident['meets_password_policy'] in "true":
            get_user_details = get_xsoar_inc(f'type:"DTM-Credential Leak" detecteduser:{incident["affectedusers"]}')
            # if get_xsoar_inc(f'alertid:"{incident["id"]}"') == 0:
            print(get_user_details)
            # exit()
            if get_user_details["total"] == 0:
                incident_count_to_be_create += 1
                print(f'need to create incident for use:"{incident["affectedusers"]}"')
                to_be_create_inc.append(incident)
                # payload = {'name': 'Allegedly leak credentials - mark.l.lindsey@us.abb.com', 'domainname': 'us.abb.com', 'type': 'DTM-Credential Leak', 'accountname': 'www.myuhc.com', 'playbook': 'DTM Credentials Leak', 'createInvestigation': True, 'alerturl': 'https://advantage.mandiant.com/dtm/alerts/cvng0c72c8r9m9904qog', 'alertname': 'Leaked Employee Credentials from "abb.com"', 'alertid': 'cvng0c72c8r9m9904qog', 'detecteduser': 'mark.l.lindsey@us.abb.com','Password_Valid_Invalid': 'In Valid', 'alerttype': 'Compromised Credentials', 'accounturl': 'www.myuhc.com', 'sourceurl': 'https://t.me/Moon_Bases/252', 'affectedusers': 'mark.l.lindsey@us.abb.com', 'occurred': '2025-04-03T21:38:42Z', 'severity': 1, 'state': 'Active'}
                get_inc_details = create_xsoar_inc(incident)
                print("creaetd_inc", get_inc_details)
                demisto.executeCommand("addToList", {"listName": "DTM-Compromised_Credentials_Invalid_Password_Report",
                                                 "listData": make_dict(incident, "Valid", get_inc_details[0].get("EntryContext").get("CreatedIncidentID"))})

            # appending the incdent with acounturl
            else:
                if get_user_details["data"][0]["status"] == 1:
                    incident_count_to_be_updated += 1
                    get_urls = get_user_details["data"][0]["CustomFields"]["accounturl"]
                    get_urls.append(incident["accounturl"])
                    print(f'need to update incident for use: {incident["affectedusers"]}: {get_urls}')
                    demisto.executeCommand("setIncident", {"id": int(get_user_details["data"][0]["id"]), "accounturl": get_urls})
                    # to_be_update_inc({'id': get_user_details["data"][0]["id"]})
        else:
            print(f'need to add in the list for use: {incident["affectedusers"]}')
            to_be_update_list.append(incident)
            incident_count_to_be_add_in_list += 1
            demisto.executeCommand("addToList", {"listName": "DTM-Compromised_Credentials_Invalid_Password_Report",
                                                 "listData": make_dict(incident, "Invalid","N/A")})

    print(f'created_inc_count==={len(to_be_create_inc)}, update_inc_count==={incident_count_to_be_updated}, update_list_count==={len(to_be_update_list)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    print(f"The script was started at {datetime.datetime.now()}")
    from_d, end_d = get_date_range()
    get_alert_data = alert_data(get_header(), from_d, end_d)
    get_data = extract_data(get_alert_data)
    unique_records = remove_duplicate(get_data)
    create_incidents(unique_records)
    print(f"The script was ended at {datetime.datetime.now()}")
