import sys
import yaml
import requests
import json
from flask import Flask
from flask import request
from docker import client

app = Flask(__name__)


@app.route('/', methods=['POST'])
def listen_to_slaves():
    print 'Payload received: {}'.format(request.data)
    headers = {'Content-Type': 'application/json'}
    consumers_list = config_json.get('consumers')
    if not consumers_list:
        return
    data = json.loads(request.data)

    node_t = {}
    d_cli = client.Client()
    for node in d_cli.nodes():
        print node
        if node.get('ID') == data['container'].get('node_id'):
            node_t = node

    data['container']['node_name'] = node_t['Description'].get('Hostname')
    del data['container']['node_id']

    data_json = json.dumps(data)
    for consumer in consumers_list:
        print 'Notifying consumer: {} with payload: {}'.format(consumer, data_json)
        requests.post(consumer, headers=headers, data=data_json)
    return '', 200


@app.route('/nodes', methods=['GET'])
def get_nodes():
    nodes = []

    d_cli = client.Client()
    for node in d_cli.nodes():
        nodes.append(node['Description'].get('Hostname'))

    response = app.response_class(
        response=json.dumps(nodes),
        status=200,
        mimetype='application/json'
    )

    return response


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print 'HELP: python notifier.py <consumers_path_file>'
        exit(1)

    with open(sys.argv[1], 'r') as f:
        config_json = yaml.load(f)

    port = config_json.get('port')

    if not port:
        print 'ERROR: Port is not set on config file'
        exit(1)

    app.run('0.0.0.0', port, debug=False)

