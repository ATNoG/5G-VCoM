import sys
import json
import subprocess
import ConfigParser
from flask import Flask
from flask import request

config = ConfigParser.ConfigParser()
app = Flask(__name__)


@app.route('/setup_c_port', methods=['POST'])
def setup_c_port():
    """
    Payload:
    {
        "br_name": "br-cpe1",
        "c_name": "vcpe1",
        "ip_address": "192.168.0.10/24",
        "gateway": "192.168.0.1",
        "mac_address": "00:00:00:00:00:00"
    }
    :return:
    """
    print 'Payload received: {}'.format(request.data)
    data = json.loads(request.data)

    # ovs-docker add-port ovs-br1 eth1 container2 --ipaddress=173.16.1.3/24 --gateway=x.x.x.x --macaddress=00:00:00:00:00:00
    cmd = [
        'sudo',
        'ovs-docker',
        'add-port',
        data.get('br_name'),
        'eth0',
        data.get('c_name'),
        '--ipaddress={}'.format(data.get('ip_address')),
        '--gateway={}'.format(data.get('gateway')),
        '--macaddress={}'.format(data.get('mac_address'))
    ]

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as cp:
        print cp
        return str(cp), 500

    return '', 200


@app.route('/setup_bridge', methods=['POST'])
def setup_bridge():
    """
    Payload:
    {
        "br_name": "br-cpe1",
        "ip_address": "192.168.0.10/24"
    }
    :return:
    """
    print 'Payload received: {}'.format(request.data)
    data = json.loads(request.data)

    try:
        subprocess.check_call(['sudo', 'ip', 'addr', 'add', data.get('ip_address'), 'dev', data.get('br_name')])
    except subprocess.CalledProcessError as cp:
        print cp
        return str(cp), 500

    try:
        subprocess.check_call(['sudo', 'ip', 'link', 'set', 'dev', data.get('br_name'), 'up'])
    except subprocess.CalledProcessError as cp:
        print cp
        return str(cp), 500

    return '', 200


@app.route('/create_bridge', methods=['POST'])
def create_bridge():
    """
    Payload:
    {
        "br_name": "br-cpe1"
    }
    :return:
    """
    print 'Payload received: {}'.format(request.data)
    data = json.loads(request.data)

    try:
        subprocess.check_call(['sudo', 'ovs-vsctl', 'add-br', data.get('br_name')])
    except subprocess.CalledProcessError as cp:
        print cp
        return str(cp), 500

    return '', 200


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print 'HELP: python agent.py <config_file>'
        exit(1)

    config.readfp(open(sys.argv[1]))

    if not config.has_option('DEFAULT', 'port'):
        print 'ERROR: Port is not set on config file'
        exit(1)

    app.run('0.0.0.0', config.get('DEFAULT', 'port'), debug=False)

