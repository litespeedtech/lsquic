import time
import json
import re
import argparse

_ev_time = 0
_ev_cate = 1
_ev_type = 2
_ev_trig = 3
_ev_data = 4
_conn_base = {
    'qlog_version': '0.1',
    'vantagepoint': 'NETWORK',
    'connectionid': '0',
    'starttime': '0',
    'fields': [
        'time',
        'category',
        'type',
        'trigger',
        'data',
    ],
    'events': [],
}

arg_parser = argparse.ArgumentParser(description='Test the ExploreParser.')
arg_parser.add_argument('qlog_path', type=str, help='path to QLog file')
args = arg_parser.parse_args()

try:
    with open(args.qlog_path, 'r') as file:
        text = file.read()
except IOError:
    print('ERROR: QLog not found at given path.')

events = {}
event_times = {}
start_time = {}

qlog = {
    'qlog_version': '0.1',
    'description': 'test with local log file',
    'connections': [],
}

lines = text.split('\n')
for line in lines:
    if 'qlog' in line:
        i = line.find('[QUIC:')
        j = line.find(']', i)
        k = line.find('qlog: ')

        cid = line[i+6:j]
        try:
            event = json.loads(line[k+6:])
        except json.JSONDecodeError:
            continue

        if not cid in events:
            events[cid] = [event]
            event_times[cid] = [event[_ev_time]]
        else:
            events[cid].append(event)
            event_times[cid].append(event[_ev_time])

for cid, times in event_times.items():
    new_events = []
    start_time[cid] = min(times)
    times = [t - min(times) for t in times]
    for t, i in sorted(((t, i) for i, t in enumerate(times))):
        events[cid][i][0] = t
        new_events.append(events[cid][i])
    events[cid] = new_events

for cid, event_list in events.items():
    conn = _conn_base.copy()
    conn['connectionid'] = cid
    conn['starttime'] = start_time[cid]
    conn['events'] = event_list
    qlog['connections'].append(conn)

print(json.dumps(qlog, indent=2))

