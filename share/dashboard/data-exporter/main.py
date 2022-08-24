import time
from prometheus_client import start_http_server, Summary, Counter, Histogram, Gauge, Enum, Info
import socketserver as SocketServer
import sys
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
import psutil
from datetime import datetime
import threading

proof_mem_gauge = Gauge('test_process_proof_mem_gauge', 'Mem usage')
proof_time_metrics = Info('test_proof_time_gauge', 'time_process_start')
mock_data = Info('test_mock_data', 'time_process_start')


def state_proof_gen_mt_process(prefix_path):
    log = open('log.txt', 'a')
    return subprocess.Popen([
        prefix_path + '/bin/state-proof-gen-mt/state-proof-gen-mt', '-i',
        prefix_path + '/bin/state-proof-gen-mt/mock.txt', "--shard0-mem-scale", "20"],
        stdout=log, stderr=log)


def get_data(prefix_path):
    log = open('get_blocks.txt', 'a')
    return subprocess.Popen(
        ["python3", prefix_path + '/../share/dashboard/data-exporter/block_data.py'], stdout=log, stderr=log)


def state_mock_process(prefix_path):
    get_data(prefix_path).wait()
    mock = open(prefix_path + '/bin/state-proof-gen-mt/mock.txt', 'w')
    return subprocess.Popen(
        [prefix_path + '/bin/state-mock/state-mock', '--input',
         prefix_path + '/../share/dashboard/data-exporter/data.json'],
        stdout=mock)


def check_htop(pid, right_name):
    global proof_mem_gauge
    while True:
        try:
            p = psutil.Process(pid)
            if (p.status() not in ['running', 'sleeping']) or (p.name() != right_name):
                proof_mem_gauge.set(0)
            else:
                proof_mem_gauge.set(p.memory_info().rss)
        except:
            proof_mem_gauge.set(0)
            return
        time.sleep(100 / 1000)  # 100ms sleep


if __name__ == '__main__':
    start_http_server(port=4005)
    BINARY_PREFIX_PATH = sys.argv[1]
    block_id = 22
    start_time = datetime.timestamp(datetime.now())
    state_mock_process(BINARY_PREFIX_PATH).wait()
    text_as_string = open(BINARY_PREFIX_PATH + '/bin/state-proof-gen-mt/mock.txt', 'r').read()
    mock_data.info({"data": text_as_string})
    proof_gen = state_proof_gen_mt_process(BINARY_PREFIX_PATH)
    right_name = psutil.Process(proof_gen.pid).name()
    start_time = datetime.timestamp(datetime.now())
    proof_time_metrics.info({"value": str(0), "blocks": str(block_id)})
    thread_mem_proof = threading.Thread(target=check_htop, args=(proof_gen.pid, right_name))
    thread_mem_proof.start()
    while True:
        if proof_gen.poll() is not None:
            proof_time_metrics.info(
                {"value": str(datetime.timestamp(datetime.now()) - start_time), "blocks": str(block_id)})
            time.sleep(15)
            proof_time_metrics.info({"value": str(0), "blocks": str(block_id)})
            thread_mem_proof.join()
            start_time = datetime.timestamp(datetime.now())
            state_mock_process(BINARY_PREFIX_PATH).wait()
            text_as_string = open(BINARY_PREFIX_PATH + '/bin/state-proof-gen-mt/mock.txt', 'r').read()
            mock_data.info({"data": text_as_string})
            proof_gen = state_proof_gen_mt_process(BINARY_PREFIX_PATH)
            thread_mem_proof = threading.Thread(target=check_htop, args=(proof_gen.pid, right_name))
            thread_mem_proof.start()
            start_time = datetime.timestamp(datetime.now())
            block_id += 1
        time.sleep(100 / 1000)  # 100 ms sleep
