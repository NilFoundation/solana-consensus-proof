#!/usr/bin/env bash

docker run -d -p 3002:9100 --name node_exporter -e TZ='ls -la /etc/localtime | cut -d/ -f8-9'  -v "/:/host:ro,rslave"   quay.io/prometheus/node-exporter
