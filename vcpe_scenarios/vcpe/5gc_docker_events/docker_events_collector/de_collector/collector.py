import docker_events
import json
import requests
import netifaces as ni


def send_notification(action, docker_event, config):
    if not config.get('master') and not config['master'].get('ip') and not config['master'].get('port'):
        return

    if not config.get('slave') and config['slave'].get('nic'):
        return

    headers = {'Content-Type': 'application/json'}

    if not docker_event.get('Actor') and not docker_event['Actor'].get('Attributes'):
        return

    attributes = docker_event['Actor']['Attributes']

    c_name = attributes.get('name')
    e_time = docker_event.get('time')
    n_id = attributes.get('com.docker.swarm.node.id')

    ext_nic_name = config['slave'].get('ext_nic')
    ip_address = ni.ifaddresses(ext_nic_name)[ni.AF_INET][0]['addr']

    target_nic_name = config['slave'].get('target_nic')
    target_mac_addr = ni.ifaddresses(target_nic_name)[ni.AF_LINK][0]['addr']

    # target interface MAC, target interface name
    payload = {'container': {
        'id': docker_event['id'],
        'name': c_name,
        'node_id': n_id},
        'vm': {
            'ext_int_ip_address': ip_address,
            'target_int_name': target_nic_name,
            'target_int_mac_addr': target_mac_addr
        },
        'action': action, 'time': e_time}
    payload_json = json.dumps(payload)
    print 'Sending payload: {}'.format(payload_json)
    requests.post('http://{}:{}'.format(config['master'].get('ip'), config['master'].get('port')),
                  headers=headers,
                  data=payload_json)


@docker_events.start.subscribe
def send_start_notification(client, docker_event, config):
    send_notification('start', docker_event, config)


@docker_events.stop.subscribe
def send_stop_notification(client, docker_event, config):
    send_notification('stop', docker_event, config)
