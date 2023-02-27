import json

from flask import Blueprint

import api.utils
from api.utils import get_jwt, jsonify_data, get_panoptica_events

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    #_ = get_jwt()
    events = get_panoptica_events()
    print(events)
    return jsonify_data({'status': 'ok'})
