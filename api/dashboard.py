import json
from urllib import response

from flask import Blueprint

from api.schemas import DashboardTileSchema, DashboardTileDataSchema
from api.utils import jsonify_data, get_jwt, get_json, get_vulnerabilities, parse_vulnerability_data, \
    return_vulnerability_tile_data, return_event_tile_data, get_risks, parse_risk_data, return_risk_tile_data, \
    get_permissions, parse_permissions_data, return_permissions_tile_data
from datetime import datetime,timedelta

dashboard_api = Blueprint('dashboard', __name__)


@dashboard_api.route('/tiles', methods=['POST'])
def tiles():
    try:
        #auth = get_jwt()
        return jsonify_data([
            {
                "title": "Panoptica Vulnerabilities",
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
                "title": "Panoptica Top Security Risks",
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
                "title": "Panoptica Permmisions and RBAC",
                "default_period": "last_24_hours",
                "id": "panoptica_permissions"
            },
            {
                "title": "Panoptica Events",
                "description": "Events Virtical Bar Chart",
                "periods": [
                    "last_hour",
                    "last_24_hours",
                    "last_7_days",
                    "last_30_days",
                ],
                "tags": [
                    "panoptica",
                    "events"
                ],
                "type": "vertical_bar_chart",
                "short_description": "The number of risky, allowed, detected, or blocked events, connections and pods",
                "id": "panoptica_events"
            },
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
    #_ = get_jwt()
    req = get_json(DashboardTileDataSchema())
    # print(req)
    if req["tile_id"] == "panoptica_vulnerabilities":
        vulnerabilities = get_vulnerabilities()
        vulnerability_list = parse_vulnerability_data(vulnerabilities)
        #print(vulnerability_list)
        data_to_graph = return_vulnerability_tile_data(vulnerability_list)
        # #print(json.dumps(data_to_graph, indent=4))
        return jsonify_data(data_to_graph)
    if req["tile_id"] == "panoptica_risks":
        risks = get_risks()
        risk_list = parse_risk_data(risks)
        data_to_graph = return_risk_tile_data(risk_list)
        return jsonify_data(data_to_graph)
    if req["tile_id"] == "panoptica_permissions":
        permissions = get_permissions()
        permissions_list = parse_permissions_data(permissions)
        data_to_graph = return_permissions_tile_data(permissions_list)
        return jsonify_data(data_to_graph)



