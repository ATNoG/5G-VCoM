#!/usr/bin/python3

import sys
import requests


"""
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {
          "instance": "10.0.0.17:9100",
          "job": "node-exporter",
          "node_name": "isp-2-swarmc-master-vdu-1"
        },
        "value": [
          1554843312.454,
          "0.23"
        ]
      },
      {
        "metric": {
          "instance": "10.0.0.18:9100",
          "job": "node-exporter",
          "node_name": "isp-2-swarmc-slave-vdu-1"
        },
        "value": [
          1554843312.454,
          "0.02"
        ]
      }
    ]
  }
}
"""


def get_loads(host):
    return requests.get('http://{}:9090/api/v1/query?query=node_load5%20*%20on(instance)%20group_left(node_name)%20node_meta%7Bnode_id%3D~%22.%2B%22%7D'.format(host), auth=('admin', 'admin')).json()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('USAGE: node_load.py <host>')
        exit(2)

    loads_json = get_loads(sys.argv[1])

    loads = loads_json['data']['result']
    min_val = 1000
    node_name = None
    for load in loads:
        if float(load['value'][1]) < min_val:
            min_val = float(load['value'][1])
            node_name = load['metric']['node_name']
    print(node_name)
