# Create Sighting

def create_sighting(hostname, xid, time):
    sighting = {
      "schema_version": "1.0.11",
      "observables": {"value": hostname, "type": "hostname"},
      "type": "sighting",
      "id": xid,
      "title": "Panoptica Event",
      "count": 1,
      "tlp": "amber",
      "source": "Panoptica",
      "description": "Automated sightings creation from Panoptica",
      "timestamp": time,
      "confidence": "High",
      "observed_time": {"start_time": time},
    }
