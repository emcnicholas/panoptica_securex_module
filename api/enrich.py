import json
from functools import partial

from flask import Blueprint, current_app, jsonify, g

from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data, fetch_panoptica_data, format_docs
import hashlib
from datetime import datetime
import time


enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


def group_observables(relay_input):
    # Leave only unique observables ( deduplicate observable )  and select some specific observable type
    result = []
    for observable in relay_input:
        o_value = observable['value']
        o_type = observable['type'].lower()

        # Get only supported types by this third party
        if o_type in current_app.config['CCT_OBSERVABLE_TYPES']:
            obj = {'type': o_type, 'value': o_value}
            if obj in result:
                continue
            result.append(obj)
    return result


def get_workload(workload):
    uri = f"podDefinitions?name={workload}"
    workload_data = fetch_panoptica_data(uri)
    return workload_data


def parse_workload_data(workload):
    for item in workload:
        if item["kind"] == "Deployment":
            hostname = item["name"]
            time = item["createdAt"]
            #print(time)
            return hostname, time


def create_sightings_xid(hostname, time):
    xid_info = f"panoptica-|sighting|{hostname}|{time}"
    sha256 = hashlib.sha256(xid_info.encode())
    result = sha256.hexdigest()
    sighting_xid = f"panoptica-sighting-{result}"
    return sighting_xid


def create_sighting(hostname, xid, time):
    time_now = datetime.utcnow().isoformat() + 'Z'
    sighting = {
        "type": "sighting",
        "source": "Panoptica",
        "source_uri": "https://appsecurity.cisco.com",
        "observables": [{
            "type": "hostname",
            "value": hostname
        }],
        "external_ids": [f"{xid}"],
        "id": f"transient:{xid}",
        "count": 1,
        "severity": "Low",
        "tlp": "green",
        "internal": True,
        "sensor": "network.sensor",
        "short_description": "Container Sighting",
        "description": "Panoptica Application Container Sighting",
        "title": "Panoptica Application Container Sighting",
        "timestamp": time_now,
        "confidence": "High",
        "observed_time": {
            "start_time": time
        },
        **current_app.config['CTIM_DEFAULTS'],
    }
    return sighting


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    g.sightings = []
    data = {}
    #_ = get_jwt()
    observables = get_observables()
    #print(observables)
    workload = group_observables(observables)
    #print(workload)
    for value in workload:
        name = value["value"]
        print(name)
        workload_data = get_workload(name)
        #print(workload_data)
        if workload_data:
            return_data = parse_workload_data(workload_data)
            #print(return_data)
            hostname = return_data[0]
            time = return_data[1]
            xid = create_sightings_xid(hostname, time)
            #print(xid)
            sighting = create_sighting(hostname, xid, time)
            #print(json.dumps(sighting))
            g.sightings.append(sighting)
            if g.sightings:
                data["sightings"] = format_docs(g.sightings)
        else:
            data = {}
    result = {'data': data}
    return jsonify(result)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # = get_jwt()
    _ = get_observables()
    return jsonify_data([])
