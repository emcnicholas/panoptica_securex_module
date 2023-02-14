from authlib.jose import jwt
from authlib.jose.errors import DecodeError, BadSignatureError
from flask import request, current_app, jsonify

from api.errors import AuthorizationError, InvalidArgumentError
from api.escherauth import EscherRequestsAuth
from datetime import datetime, timedelta
import requests
import json

access_key = "4441f34a-a7c4-40a9-8d12-daf67d5727cd"
secret_key = "oL4G1e7s14FmBFcaxAnLMmsq7SEGlHPqxuhJZBqaOUY="



def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        return jwt.decode(token, current_app.config['SECRET_KEY'])['key']
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})


def fetch_panoptica_data(
        uri,
        host="securecn.cisco.com",
        api_key = access_key,
        api_sec = secret_key
):
    date_format = '%Y%m%dT%H%M%SZ'
    date_string = datetime.utcnow().strftime(date_format)
    date = datetime.strptime(date_string, date_format)

    # Build URL
    url = f"https://{host}/api/{uri}"
    headers = {'X-Escher-Date': date_string,
               'host': url.split(':')[0],
               'content-type': 'application/json'}
    auth = EscherRequestsAuth("global/services/portshift_request",
                                         {'current_time': date},
                                         {'api_key': api_key, 'api_secret': api_sec})

    # HTTP Get Request
    response = requests.get(url, headers=headers, auth=auth)

    # If response code is 200, then return the json response
    if response.status_code == 200:
        # JSON Response
        json_response = response.json()

        return json_response

    # If response code is anything but 200, print error message with response code
    else:
        print(f"An error has ocurred, while fetching alerts, with the following code {response.status_code}")


def get_vulnerabilities():
    uri = "dashboard/vulnerabilities"
    vulnerabilities = fetch_panoptica_data(uri)
    # print(json.dumps(vulnerabilities, indent=4))
    return vulnerabilities


def parse_vulnerability_data(vulnerabilities):
    vulnerability_list = []
    for severity in vulnerabilities["WorkloadVulnerabilitiesWidget"]["bars"]:
        if severity["severity"] == "UNKNOWN":
            pod_unknown_vuln = severity["count"]
            vulnerability_list.append(pod_unknown_vuln)
        if severity["severity"] == "LOW":
            pod_low_vuln = severity["count"]
            vulnerability_list.append(pod_low_vuln)
        if severity["severity"] == "MEDIUM":
            pod_med_vuln = severity["count"]
            vulnerability_list.append(pod_med_vuln)
        if severity["severity"] == "HIGH":
            pod_high_vuln = severity["count"]
            vulnerability_list.append(pod_high_vuln)
        if severity["severity"] == "CRITICAL":
            pod_critical_vuln = severity["count"]
            vulnerability_list.append(pod_critical_vuln)
    for severity in vulnerabilities["ServerlessVulnerabilitiesWidget"]["bars"]:
        if severity["severity"] == "UNKNOWN":
            pod_unknown_vuln = severity["count"]
            vulnerability_list.append(pod_unknown_vuln)
        if severity["severity"] == "LOW":
            pod_low_vuln = severity["count"]
            vulnerability_list.append(pod_low_vuln)
        if severity["severity"] == "MEDIUM":
            pod_med_vuln = severity["count"]
            vulnerability_list.append(pod_med_vuln)
        if severity["severity"] == "HIGH":
            pod_high_vuln = severity["count"]
            vulnerability_list.append(pod_high_vuln)
        if severity["severity"] == "CRITICAL":
            pod_critical_vuln = severity["count"]
            vulnerability_list.append(pod_critical_vuln)
    return vulnerability_list


def return_vulnerability_tile_data(vulnerability_list):
    vl = vulnerability_list
    pod_unk, pod_low, pod_med, pod_high, pod_crit, sl_unk, sl_low, sl_med, sl_high, sl_crit = vl[0], vl[1], vl[2], vl[3], vl[4], vl[5], vl[6], vl[7], vl[8], vl[9]
    # print(pod_unk, pod_low, pod_med, pod_high, pod_crit, sl_unk, sl_low, sl_med, sl_high, sl_crit)
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    datetime_now = datetime.utcnow()
    datetime_now_str = datetime_now.strftime(date_format)
    datetime_minus5 = datetime_now - timedelta(minutes=5)
    datetime_minus5_str = datetime_minus5.strftime(date_format)
    panoptica_vul_data = {
        "valid_time": {
            "start_time": datetime_minus5_str,
            "end_time": datetime_now_str
        },
        "tile_id": "panoptica_vulnerabilities",
        "keys": [
            {
                "key": "pods",
                "label": "PODS"
            },
            {
                "key": "serverless",
                "label": "SERVERLESS"
            }
        ],
        "cache_scope": "user",
        "key_type": "string",
        "period": "last_24_hours",
        "observed_time": {
            "start_time": datetime_minus5_str,
            "end_time": datetime_now_str
        },
        "data": [
            {
                "key": "Critical",
                "value": (pod_crit + sl_crit),
                "values": [
                    {
                        "key": "pods",
                        "value": pod_crit,
                        "link_uri": "https://securecn.cisco.com/runtime/workloads"
                    },
                    {
                        "key": "serverless",
                        "value": sl_crit,
                        "link_uri": f"https://securecn.cisco.com/serverless/functions"
                    }
                ]
            },
            {
                "key": "High",
                "value": (pod_high + sl_high),
                "values": [
                    {
                        "key": "pods",
                        "value": pod_high,
                        "link_uri": "https://securecn.cisco.com/runtime/workloads"
                    },
                    {
                        "key": "serverless",
                        "value": sl_high,
                        "link_uri": f"https://securecn.cisco.com/serverless/functions"
                    }
                ]
            },
            {
                "key": "Medium",
                "value": (pod_med + sl_med),
                "values": [
                    {
                        "key": "pods",
                        "value": pod_med,
                        "link_uri": f"https://securecn.cisco.com/runtime/workloads"
                    },
                    {
                        "key": "serverless",
                        "value": sl_med,
                        "link_uri": f"https://securecn.cisco.com/serverless/functions"
                    }
                ]
            },
            {
                "key": "Low",
                "value": (pod_low + sl_low),
                "values": [
                    {
                        "key": "pods",
                        "value": pod_low,
                        "link_uri": f"https://securecn.cisco.com/runtime/workloads"
                    },
                    {
                        "key": "serverless",
                        "value": sl_low,
                        "link_uri": f"https://securecn.cisco.com/serverless/functions"
                    }
                ]
            },
            {
                "key": "Unknown",
                "value": (pod_unk + sl_unk),
                "values": [
                    {
                        "key": "pods",
                        "value": pod_unk,
                        "link_uri": f"https://securecn.cisco.com/runtime/workloads"
                    },
                    {
                        "key": "serverless",
                        "value": sl_unk,
                        "link_uri": f"https://securecn.cisco.com/serverless/functions"
                    }
                ]
            }
        ]
    }
    # print(json.dumps(panoptica_vul_data, indent=4))
    return panoptica_vul_data


def get_risks():
    uri = "dashboard/topSecurityRisks?size=10"
    risks = fetch_panoptica_data(uri)
    # print(json.dumps(risks, indent=4))
    return risks


def parse_risk_data(risks):
    risks_list = []
    for pod in risks["topRiskyWorkloadsWidget"]["topRiskyWorkloads"]:
        pod_name, pod_risk = pod["name"], pod["risk"]
        workload_risks = {"type": "pod", "name": pod_name, "risk": pod_risk}
        risks_list.append(workload_risks)
    for api in risks["topRiskyApisWidget"]["topRiskyApis"]:
        api_name, api_risk = api["name"], api["risk"]
        api_risks = {"type": "api", "name": api_name, "risk": api_risk}
        risks_list.append(api_risks)
    for serverless in risks["topRiskyServerlessFunctionsWidget"]["topRiskyServerlessFunctions"]:
        serverless_name, serverless_risk = serverless["name"], serverless["risk"]
        serverless_risks = {"type": "serverless", "name": serverless_name, "risk": serverless_risk}
        risks_list.append(serverless_risks)
    return risks_list


def return_risk_tile_data(risk_list):
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    datetime_now = datetime.utcnow()
    datetime_now_str = datetime_now.strftime(date_format)
    datetime_minus5 = datetime_now - timedelta(minutes=5)
    datetime_minus5_str = datetime_minus5.strftime(date_format)
    markdown = [
        "| Type | Name | Risk |",
        "| :-- | --- | --: |"
    ]
    for risk in risk_list:
        type, name = risk["type"].upper(), risk["name"]
        if risk["risk"] == "CRITICAL":
            risk = "💀 CRITICAL"
        elif risk["risk"] == "HIGH":
            risk = "❗ HIGH"
        elif risk["risk"] == "MEDIUM":
            risk = "⚠️MEDIUM"
        elif risk["risk"] == "LOW":
            risk = "⛅ LOW"
        else:
            risk = "❓ UNKNOWN"
        md_risk = f"| **{type}** | **{name}** | **{risk}** |"
        # print(md_risk)
        markdown.append(md_risk)
    panoptica_risks = {
        "valid_time": {
            "start_time": datetime_minus5_str,
            "end_time": datetime_now_str
        },
        "tile_id": "panoptica_risks",
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": datetime_minus5_str,
            "end_time": datetime_now_str
        },
        "data": markdown
    }
    return panoptica_risks


def return_event_tile_data():
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    datetime_now = datetime.utcnow()
    datetime_now_str = datetime_now.strftime(date_format)
    datetime_minus5 = datetime_now - timedelta(microseconds=5)
    datetime_minus5_str = datetime_minus5.strftime(date_format)
    panoptica_event_data = {
        "cache_scope": "org",
        "data": [
            {"key": 1611731572, "value": 13},
            {"key": 1611645172, "value": 20},
            {"key": 1611558772, "value": 5},
            {"key": 1611431572, "value": 13},
            {"key": 1611345172, "value": 20},
            {"key": 1611258772, "value": 5},
            {"key": 1611131572, "value": 13},
            {"key": 1611045172, "value": 20},
            {"key": 1610958772, "value": 5},
            {"key": 1610831572, "value": 13},
            {"key": 1610745172, "value": 20},
            {"key": 1610658772, "value": 5},
            {"key": 1610531572, "value": 13},
            {"key": 1610445172, "value": 20},
            {"key": 1610358772, "value": 5},
        ]
    }
    print(panoptica_event_data)
    return panoptica_event_data


def get_permissions():
    uri = "dashboard/permissions?includeSystemOwners=false"
    permissions = fetch_panoptica_data(uri)
    return permissions


def parse_permissions_data(permissions):
    permissions_list = []
    for risks in permissions["bars"]:
        if risks["risk"] == "NO_RISK":
            no_risk_permissions, no_risk_owners = risks["count"], risks["onwers"]
            permissions_list.extend([no_risk_permissions, no_risk_owners])
        if risks["risk"] == "MEDIUM":
            med_permissions, med_owners = risks["count"], risks["onwers"]
            permissions_list.extend([med_permissions, med_owners])
        if risks["risk"] == "HIGH":
            high_permissions, high_owners = risks["count"], risks["onwers"]
            permissions_list.extend([high_permissions, high_owners])
        if risks["risk"] == "APPROVED":
            approved_permissions, approved_owners = risks["count"], risks["onwers"]
            permissions_list.extend([approved_permissions, approved_owners])
    return permissions_list


def return_permissions_tile_data(permissions_list):
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    datetime_now = datetime.utcnow()
    datetime_now_str = datetime_now.strftime(date_format)
    datetime_minushour = datetime_now - timedelta(hours=1)
    datetime_minushour_str = datetime_minushour.strftime(date_format)
    pl = permissions_list
    nr_perm, nr_own, med_perm, med_own, high_perm, high_own, appr_perm, appr_own = pl[0], pl[1], pl[2], pl[3], pl[4], pl[5], pl[6], pl[7]
    panoptica_permissions_data = {
        "labels": [
            [
                "No Risk",
                "Medium",
                "High",
                "Approved"
            ],
            [
                "Permissions",
                "Owners"
            ]
        ],
        "valid_time": {
            "start_time": datetime_minushour_str,
            "end_time": datetime_now_str
        },
        "tile_id": "panoptica_permissions",
        "cache_scope": "user",
        "period": "last_hour",
        "observed_time": {
            "start_time": datetime_minushour_str,
            "end_time": datetime_now_str
        },
        "color_scale": "status",
        "data": [
            {
                "key": 0,
                "value": (nr_perm + nr_own),
                "segments": [
                    {
                        "key": 0,
                        "value": nr_perm
                    },
                    {
                        "key": 1,
                        "value": nr_own
                    }
                ]
            },
            {
                "key": 1,
                "value": (med_perm + med_own),
                "segments": [
                    {
                        "key": 0,
                        "value": med_perm
                    },
                    {
                        "key": 1,
                        "value": med_own
                    }
                ]
            },
            {
                "key": 2,
                "value": (high_perm + high_own),
                "segments": [
                    {
                        "key": 0,
                        "value": high_perm
                    },
                    {
                        "key": 1,
                        "value": high_own
                    }
                ]
            },
            {
                "key": 3,
                "value": (appr_perm + appr_own),
                "segments": [
                    {
                        "key": 0,
                        "value": appr_perm
                    },
                    {
                        "key": 1,
                        "value": appr_own
                    }
                ]
            }
        ]
    }
    return panoptica_permissions_data

