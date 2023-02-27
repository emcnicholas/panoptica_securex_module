import json
from urllib import response

from flask import Blueprint

import api.utils
from api.schemas import DashboardTileSchema, DashboardTileDataSchema
from api.utils import jsonify_data, get_jwt, get_json, get_vulnerabilities, parse_vulnerability_data, \
    return_vulnerability_tile_data, return_event_tile_data, get_risks, parse_risk_data, return_risk_tile_data, \
    get_permissions, parse_permissions_data, return_permissions_tile_data
from datetime import datetime,timedelta

dashboard_api = Blueprint('dashboard', __name__)


@dashboard_api.route('/tiles', methods=['POST'])
def tiles():
    try:
        # = get_jwt()
        return jsonify_data([
            {
                "title": "Workload and Serverless Vulnerabilities",
                "description": "Horizontal Bar Chart",
                "periods": [
                    "last_hour"
                ],
                "default_period": "last_hour",
                "type": "horizontal_bar_chart",
                "short_description": "Pod and Serverless Vulnerabilities",
                "id": "panoptica_vulnerabilities",
                "tags": [
                    "panoptica",
                    "vulnerabilities"
                ]
            },
            {
                "title": "Top Workload Security Risks",
                "description": "A Markdown Tile",
                "periods": [
                    "last_hour"
                ],
                "tags": [
                    "panoptica",
                    "risks"
                ],
                "type": "markdown",
                "short_description": "Security risk for Pods, APIs and Serverless",
                "id": "panoptica_risks"
            },
            {
                "description": "DONUTS",
                "periods": [
                    "last_hour"
                ],
                "tags": [
                    "panoptica",
                    "permissions"
                ],
                "type": "donut_graph",
                "short_description": "Panoptica (RBAC)",
                "title": "Permmisions and RBAC",
                "default_period": "last_hour",
                "id": "panoptica_permissions"
            },
            {
                "description": "DONUTS",
                "periods": [
                    "last_hour"
                ],
                "tags": [
                    "panoptica",
                    "api",
                    "risks"
                ],
                "type": "donut_graph",
                "short_description": "Internal and External API Risks",
                "title": "API Risks",
                "default_period": "last_hour",
                "id": "panoptica_api_risks"
            },
            {
                "title": "Top Internal Risky API Findings",
                "description": "A Markdown Tile",
                "periods": [
                    "last_hour"
                ],
                "tags": [
                    "panoptica",
                    "risks",
                    "internal"
                ],
                "type": "markdown",
                "short_description": "Top 5 risky findings for internal APIs",
                "id": "panoptica_int_risky_findings"
            },
            {
                "title": "Top External Risky API Findings",
                "description": "A Markdown Tile",
                "periods": [
                    "last_hour"
                ],
                "tags": [
                    "panoptica",
                    "risks",
                    "external"
                ],
                "type": "markdown",
                "short_description": "Top 5 risky findings for external APIs",
                "id": "panoptica_ext_risky_findings"
            }
        ])
    except:
        return jsonify_data([])


@dashboard_api.route('/tiles/tile', methods=['POST'])
def tile():
    _ = get_jwt()
    _ = get_json(DashboardTileSchema())
    return jsonify_data({})


@dashboard_api.route('/tiles/tile-data', methods=['POST'])
def tile_data():
    #jwt_resp = get_jwt()
    #print(jwt_resp)
    req = get_json(DashboardTileDataSchema())
    #print(req)
    if req["tile_id"] == "panoptica_vulnerabilities":
        period = req["period"]
        time = api.utils.get_timeframe(period)
        start_time, end_time = time["start_time"], time["end_time"]
        vulnerabilities = get_vulnerabilities()
        vulnerability_list = parse_vulnerability_data(vulnerabilities)
        #print(vulnerability_list)
        data_to_graph = return_vulnerability_tile_data(vulnerability_list, start_time, end_time)
        # #print(json.dumps(data_to_graph, indent=4))
        return jsonify_data(data_to_graph)
    elif req["tile_id"] == "panoptica_risks":
        period = req["period"]
        time = api.utils.get_timeframe(period)
        start_time, end_time = time["start_time"], time["end_time"]
        risks = get_risks()
        risk_list = parse_risk_data(risks)
        data_to_graph = return_risk_tile_data(risk_list, start_time, end_time)
        return jsonify_data(data_to_graph)
    elif req["tile_id"] == "panoptica_permissions":
        period = req["period"]
        time = api.utils.get_timeframe(period)
        start_time, end_time = time["start_time"], time["end_time"]
        permissions = get_permissions()
        permissions_list = parse_permissions_data(permissions)
        data_to_graph = return_permissions_tile_data(permissions_list, start_time, end_time)
        return jsonify_data(data_to_graph)
    elif req["tile_id"] == "panoptica_api_risks":
        period = req["period"]
        time = api.utils.get_timeframe(period)
        start_time, end_time = time["start_time"], time["end_time"]
        int_risks = api.utils.get_internal_api_risks()
        ext_risks = api.utils.get_external_api_risks()
        int_risks_list, ext_risks_list = api.utils.parse_api_risks(int_risks, ext_risks)
        data_to_graph = api.utils.return_api_risks_data(int_risks_list, ext_risks_list, start_time, end_time)
        #print(json.dumps(data_to_graph, indent=4))
        return jsonify_data(data_to_graph)
    elif req["tile_id"] == "panoptica_int_risky_findings":
        period = req["period"]
        time = api.utils.get_timeframe(period)
        start_time, end_time = time["start_time"], time["end_time"]
        int_findings = api.utils.get_internal_risky_findings()
        data_to_graph = api.utils.return_internal_risky_data(int_findings, start_time, end_time)
        return jsonify_data(data_to_graph)
    elif req["tile_id"] == "panoptica_ext_risky_findings":
        period = req["period"]
        time = api.utils.get_timeframe(period)
        start_time, end_time = time["start_time"], time["end_time"]
        ext_findings = api.utils.get_external_risky_findings()
        data_to_graph = api.utils.return_external_risky_data(ext_findings, start_time, end_time)
        return jsonify_data(data_to_graph)
