import time
from prometheus_client import start_http_server, Summary, Counter, Histogram, Gauge, Enum, Info
import socketserver as SocketServer
import sys
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
import psutil
from datetime import datetime
import threading
import block_data
import validators_exporter
import json

proof_mem_gauge = Gauge('process_proof_mem', 'Mem usage', ['project', 'proof'])
proof_time_metrics = Info('proof_time', 'Proof time generation', ['project', 'proof'])
mock_data = Info('mock_data', 'Mock data in json', ['project', 'proof'])
proof_data = Info('proof_data', 'Proof data in hex', ['project', 'proof'])
confirmed_block = 0
project = 'solana'
proof_name = 'placeholder'


def state_proof_gen_mt_process(prefix_path):
    log = open('log.txt', 'a')
    return subprocess.Popen([
        prefix_path + '/bin/state-proof-gen-mt/state-proof-gen-mt', '-i',
        prefix_path + '/bin/state-proof-gen-mt/mock.txt', "--shard0-mem-scale", "20"],
        stdout=log, stderr=log)


def state_mock_process(prefix_path):
    global confirmed_block
    state, confirmed_block = block_data.get_data(confirmed_block)
    with open(prefix_path + '/bin/state-mock/data.json', 'w') as f:
        print(json.dumps(state.json(), indent=2), file=f)
    mock = open(prefix_path + '/bin/state-proof-gen-mt/mock.txt', 'w')
    return subprocess.Popen(
        [prefix_path + '/bin/state-mock/state-mock', '--input',
         prefix_path + '/bin/state-mock/data.json', '--validators', str(validators_exporter.get_validators_count())],
        stdout=mock)


def check_htop(pid, right_name):
    global proof_mem_gauge
    while True:
        try:
            p = psutil.Process(pid)
            if (p.status() not in ['running', 'sleeping']) or (p.name() != right_name):
                proof_mem_gauge.labels(project, proof_name).set(0)
            else:
                proof_mem_gauge.labels(project, proof_name).set(p.memory_info().rss)
        except:
            proof_mem_gauge.labels(project, proof_name).set(0)
            return
        time.sleep(100 / 1000)  # 100ms sleep


if __name__ == '__main__':
    start_http_server(port=4005)
    BINARY_PREFIX_PATH = sys.argv[1]
    start_time = datetime.timestamp(datetime.now())
    state_mock_process(BINARY_PREFIX_PATH).wait()
    text_as_string = open(BINARY_PREFIX_PATH + '/bin/state-proof-gen-mt/mock.txt', 'r').read()
    mock_data.labels(project, proof_name).info({"data": text_as_string})
    proof_gen = state_proof_gen_mt_process(BINARY_PREFIX_PATH)
    right_name = psutil.Process(proof_gen.pid).name()
    start_time = datetime.timestamp(datetime.now())
    proof_time_metrics.labels(project, proof_name).info({"value": str(0), "blocks": str(confirmed_block)})
    thread_mem_proof = threading.Thread(target=check_htop, args=(proof_gen.pid, right_name))
    thread_mem_proof.start()
    while True:
        if proof_gen.poll() is not None:
            proof_time_metrics.labels(project, proof_name).info(
                {"value": str(datetime.timestamp(datetime.now()) - start_time), "blocks": str(confirmed_block)})
            proof = open('./placeholder_proof.data', 'r').read()
            proof_data.labels(project, proof_name).info({"data": proof})
            time.sleep(15)
            proof_time_metrics.labels(project, proof_name).info({"value": str(0), "blocks": str(confirmed_block)})
            thread_mem_proof.join()
            start_time = datetime.timestamp(datetime.now())
            state_mock_process(BINARY_PREFIX_PATH).wait()
            text_as_string = open(BINARY_PREFIX_PATH + '/bin/state-proof-gen-mt/mock.txt', 'r').read()
            mock_data.labels(project, proof_name).info({"data": text_as_string})
            proof_gen = state_proof_gen_mt_process(BINARY_PREFIX_PATH)
            thread_mem_proof = threading.Thread(target=check_htop, args=(proof_gen.pid, right_name))
            thread_mem_proof.start()
            start_time = datetime.timestamp(datetime.now())
        time.sleep(100 / 1000)  # 100 ms sleep
