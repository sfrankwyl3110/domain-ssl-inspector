import json
import logging
import os.path
import ssl
import socket
import sys
import threading
import time
import uuid
import tldextract
import pandas as pd
from datetime import datetime
from schedule import Scheduler


def setup_logging(log_filename=None, log_filemode=None, log_debug_level=None) -> logging.Logger:
    logger = logging.getLogger('ssl_inspect.py')

    logger.setLevel(logging.DEBUG if log_debug_level is None else log_debug_level)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
        datefmt='%d.%m.%Y %H:%M:%S'
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # create file handler and set level to debug
    ch = logging.FileHandler(
        filename="ssl_inspect.log" if log_filename is None else log_filename,
        mode="a" if log_filemode is None else log_filemode
    )
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


def is_valid_tld(tld):
    extracted = tldextract.extract("." + tld)
    return bool(extracted.suffix)


def sec_converter(seconds_left):
    days_ = seconds_left / 60 / 60 / 24
    return days_


def calc_expiration_seconds(cert: dict) -> int:
    expire_end = cert.get("notAfter")
    datetime_obj_end = datetime.strptime(expire_end, '%b %d %H:%M:%S %Y %Z')
    time_left = datetime_obj_end - datetime.now()
    seconds_left = time_left.total_seconds()
    return int(seconds_left)


def get_ssl_info(current_req_uuid, url: str) -> dict:
    cert = {}
    context = ssl.create_default_context()
    with socket.create_connection((url, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=url) as ssl_sock:
            try:
                cert = ssl_sock.getpeercert()
            except ValueError:
                pass
    return {current_req_uuid: cert, "requested": time.time()}


def read_csv_file(filepath):
    df = pd.read_csv(filepath)
    return df.to_dict('records')


def update_csv_file(filename, current_domain, last_check, last_expire_seconds):
    df = pd.read_csv(filename)

    # Find the row with the desired domain
    mask = df['domain'] == current_domain

    # Update the values in the row
    if df.loc[mask, 'added'].iloc[0] == 0:
        df.loc[mask, 'added'] = time.time()
    df.loc[mask, 'last_check'] = last_check
    df.loc[mask, 'last_expire_seconds'] = last_expire_seconds

    # Write the modified data frame back to the CSV file
    df.to_csv(filename, index=False)


def request_ssl_info(current_tld) -> str:
    req_uuid = str(uuid.uuid4())
    ssl_info = get_ssl_info(req_uuid, current_tld)

    df = pd.DataFrame(
        columns=['uuid', 'domain', 'subject', 'issuer', 'version', 'serialNumber', 'notBefore', 'notAfter',
                 'subjectAltName', 'OCSP', 'caIssuers', 'crlDistributionPoints', 'requested'])

    for uuid_, info in ssl_info.items():
        if isinstance(info, float):
            df.loc[0, 'requested'] = info
        if isinstance(info, dict):
            subject = info["subject"] if "subject" in info.keys() else ""
            df.loc[0] = [req_uuid, current_tld, subject, info['issuer'], info['version'], info['serialNumber'],
                         info['notBefore'], info['notAfter'], info['subjectAltName'], info['OCSP'], info['caIssuers'],
                         info['crlDistributionPoints'] if 'crlDistributionPoints' in info.keys() else "", ""]
    if not df.empty:
        filename = "ssl_info.csv"
        current_filemode = 'w' if not os.path.isfile(filename) else 'a'
        df.to_csv(filename, mode=current_filemode, header=current_filemode == "w", index=False)
        return df.to_json(orient='records')


class JobScheduler(threading.Thread):
    running = True
    last_r = None
    scheduler_interval_seconds = 10
    executions = {}

    def job(self, current_domain):
        if current_domain not in self.executions.keys():
            self.executions[current_domain] = {
                "last_job": time.time(),
                "count": 1
            }
        else:
            self.executions[current_domain]["last_job"] = time.time()
            self.executions[current_domain]["count"] += 1
        for domain_k in self.executions.keys():
            self.logger.debug("{}: count {}".format(domain_k, self.executions[domain_k]["count"]))

        self.logger.info("{}: requesting ssl-info ...".format(
            current_domain
        ))

        update_csv_file('domains.csv', current_domain, time.time(),
                        calc_expiration_seconds(json.loads(request_ssl_info(current_domain))[0])
                        )
        self.last_r = current_domain

    def __init__(self):
        self.logger = setup_logging()
        self.scheduler = Scheduler()
        self.setup_jobs()
        super().__init__()

    def setup_jobs(self):
        if os.path.isfile("domains.csv"):
            domains_csv = read_csv_file("domains.csv")
            for domain_entry in domains_csv:
                current_domain = domain_entry["domain"] if "domain" in domain_entry.keys() else ""
                self.logger.debug("adding domain: {}".format(current_domain))
                interval_seconds = int(domain_entry.get("interval"))
                self.scheduler_interval_seconds = interval_seconds
                self.scheduler.every(self.scheduler_interval_seconds).seconds.do(self.job, current_domain)
                if interval_seconds > 60:
                    self.job(current_domain)

    def run(self):
        while self.running:
            self.scheduler.run_pending()
            time.sleep(1)


schedulers = []


def check_alive():
    one_alive = False
    for s in schedulers:
        if isinstance(s, JobScheduler) and s.is_alive():
            one_alive = True

    return one_alive


if __name__ == '__main__':
    if len(sys.argv) > 1:
        domain_tld = sys.argv[1]
        if is_valid_tld(domain_tld):
            request_ssl_info(domain_tld)
        else:
            print("err: not a valid tld")
    else:
        job_scheduler = JobScheduler()
        job_scheduler.daemon = True
        job_scheduler.start()
        try:
            while job_scheduler.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            job_scheduler.running = False
