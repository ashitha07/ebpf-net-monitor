import sys
import json
import argparse
from datetime import datetime
from opensearchpy import OpenSearch

# OpenSearch connection
client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    # no auth for local dev
)

INDEX_NAME = f"ebpf-net-monitor-{datetime.now().strftime('%Y-%m-%d')}"

def index_event(event,skip_opensearch=False):
    if skip_opensearch:
        return
    try:
        client.index(index=INDEX_NAME, body=event)
    except Exception as e:
        print(f"Error indexing event: {e}")

def main():
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-opensearch", action="store_true")
    args = parser.parse_args()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            # parse JSON
            # index to OpenSearch
            # if it's an alert, print to console
            event = json.loads(line)
            index_event(event,args.no_opensearch)
            print(f"Indexed: {event['event']} {event['dst_ip']}:{event['dst_port']}", flush=True)
            pass
        except json.JSONDecodeError:
            # handle non-JSON lines (like port scan alerts)
            print(line, flush=True)  # just print them as-is

if __name__ == "__main__":
    main()