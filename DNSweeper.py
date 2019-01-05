# MIT License
#
# Copyright (c) 2018 Petr Javorik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import aiodns
import argparse
import asyncio
import csv
import ipaddress
import json
import os
import pathlib
import platform
import random
import re
import resource
import requests
import socket
import string
import subprocess
import sys
import time

import data.trusted_resolvers as data

###########################################
# CONSTANTS
###########################################

## CORE
AIODNS_TIMEOUT = 5
AIODNS_RETRY = 3
MAXIMUM_CONCURRENT_COROS = 20000
THROTTLE_EVENT_LOOP_SEC = 1
# Increase maximum number of opened file descriptors
RLIMIT_NOFILE_TEMP = 25000

## DEFAULTS
# DNSresolver will use just public resolvers with minimum reliability >= MIN_RELIABILITY
# More details on https://public-dns.info
MIN_RELIABILITY = '1.00'
SWEEP_MODES = ['resolvers', 'names']
RESOLVERS_SWEEP_RESERVE = 50

# Do not use more than PUB_NS_LIMIT public resolvers
PUB_NS_LIMIT = 20000

# By default DNSweeper.garbage_query_filter() filters out resolvers which return valid answers to questions like
# vnfjdkmcniusd.<test_domain>.com
# If 2 rounds of filtering enabled DNSweeper.garbage_query_filter() additionally queries subdomains like
# njvinkdlsfjv.nncvkdsdfu.<test_domain>.com
FILTER2ROUNDS = False

## PATHS
IPTOASN_API_URL = 'whois.cymru.com'
IPTOASN_API_PORT = 43
PUBLIC_RESOLVERS_REMOTE_SOURCE = 'https://public-dns.info/nameservers.csv'
PUBLIC_RESOLVERS_LOCAL_SOURCE = os.path.dirname(os.path.realpath(__file__)) + '/data/nameservers.csv'
DEFAULT_BRUTEFORCE_PAYLOAD = os.path.dirname(os.path.realpath(__file__)) + '/data/bitquark-subdomains-top100K.txt_ascii'
DEFAULT_CACHE_DIR = os.getcwd() + '/cache/'

## OUTPUT
# Output JSON formatting
DEFAULT_OUTPUT_DIR = os.getcwd() + '/results/'
JSON_INDENT = 2


class DNSweeper(object):

    def __init__(self):

        # asyncio
        self.loop = asyncio.get_event_loop()
        self.sem = asyncio.Semaphore(MAXIMUM_CONCURRENT_COROS, loop=self.loop)

        # aiodns
        self.timeout = AIODNS_TIMEOUT
        self.retry = AIODNS_RETRY

        # args
        # Initialize self.args via CLI (see App.__init__:)
        # or directly via DNSweeper if used in python scripts
        # This dictionary is considered to be interface between the App and DNSweeper methods
        self.args = {
            'file_input': '',
            'domain_input': '',
            'output_dir': '',
            'payload_file': '',
            'exclude_file': '',
            'reverse_regex': '',
            'bruteforce_recursive': '',
            'fast_sweep': False,
            'use_cache': False,
            'no_bruteforce': False,
            'verbosity': 0
        }

        self.exclude_subdomains = []

        # others
        self.public_resolvers_remote_source = PUBLIC_RESOLVERS_REMOTE_SOURCE
        self.public_resolvers_local_source = PUBLIC_RESOLVERS_LOCAL_SOURCE


    ################################################################################
    # CORE
    ################################################################################

    async def _query_sweep_resolvers(self, name, query_type, nameserver):

        async with self.sem:
            resolver = aiodns.DNSResolver(
                nameservers=[nameserver],
                timeout=self.timeout,
                tries=self.retry,
                loop=self.loop
            )

            try:
                result = await resolver.query(name, query_type)
            except aiodns.error.DNSError as e:
                result = e

            return {'ns': nameserver,'name': name ,'type': query_type, 'result': result}

    @staticmethod
    async def _query_sweep_names(name, query_type, resolver):

        try:
            result = await resolver.query(name, query_type)
        except aiodns.error.DNSError as e:
            result = e

        return {'name': name, 'type': query_type, 'result': result}

    def _get_records(self, names, query_type, resolvers, sweep_mode):

        if sweep_mode not in SWEEP_MODES:
            raise ValueError('Invalid sweep_mode. Valid sweep_modes: [resolvers, names]')

        self._check_tcp_limit()

        records = []
        if sweep_mode == 'resolvers':
            self.simple_log('## Getting records in sweep_mode: {}'.format(sweep_mode), 2)

            # MULTIPLE DNSResolvers for ONE name
            coros = [self._query_sweep_resolvers(names, query_type, resolver) for resolver in resolvers]
            tasks = asyncio.gather(*coros, return_exceptions=True)

            start = time.time()
            self.simple_log('## Starting event loop...'.format(), 2)
            records = self.loop.run_until_complete(tasks)
            end = time.time()
            elapsed_time = end - start

            request_count = len(coros)
            self.simple_log('## Event loop finished {} requests in {:.1f} seconds'.format(request_count, elapsed_time), 2)
            self.simple_log('## which is {:.1f} requests per second'.format(request_count / elapsed_time), 2)

        elif sweep_mode == 'names':
            self.simple_log('## Getting records in sweep_mode: {}'.format(sweep_mode), 2)

            # Special case for 1 domain input fix
            if isinstance(names, str):
                names = [names]

            # ONE DNSResolver for MULTIPLE 'names'
            resolver = aiodns.DNSResolver(
                nameservers=resolvers,
                timeout=self.timeout,
                tries=self.retry,
                loop=self.loop,
                rotate=True
            )

            # Process event loop in batches for large amount of names.
            #
            # Short description:
            # ONE call to ONE resolver per ONE event loop execution.
            #
            # Long description:
            # We don't want to resolve more than len(names) queries in
            # one event loop run what would mean more than 1 query per resolver.
            # Some resolvers might return error and in that case pycares Channel will use next available resolver.
            # Assuming that no more than RESOLVERS_SWEEP_RESERVE will return errors so that underlying pycares Channel
            # will not start iterating resolvers from the beginning again.

            def chunks(l, n):
                """Yield successive n-sized chunks from l."""
                for i in range(0, len(l), n):
                    yield l[i:i + n]

            chunk_size = len(resolvers) - RESOLVERS_SWEEP_RESERVE if len(resolvers) > RESOLVERS_SWEEP_RESERVE else len(resolvers)
            self.simple_log('## Calculated chunk_size: {}'.format(chunk_size), 2)
            chunk_list = list(chunks(names, chunk_size))
            self.simple_log('## Calculated chunk_size list length: {}'.format(len(chunk_list)), 2)
            chunk_n = 0
            requests_processed = 0
            outer_start = time.time()
            for chunk in chunk_list:

                coros = [self._query_sweep_names(name, query_type, resolver) for name in chunk]
                tasks = asyncio.gather(*coros, return_exceptions=True)

                start = time.time()
                self.simple_log('## Starting event loop for chunk {}...'.format(chunk_n), 2)
                chunk_n += 1
                records_batch = self.loop.run_until_complete(tasks)
                end = time.time()
                elapsed_time = end - start

                request_count = len(coros)
                self.simple_log('## Chunk event loop finished {} requests in {:.1f} seconds'.format(request_count, elapsed_time), 2)
                self.simple_log('## which is {:.1f} requests per second'.format(request_count / elapsed_time), 2)

                requests_processed += request_count
                self.simple_log('## Total requests processed: {}'.format(requests_processed), 2)
                records.extend(records_batch)
                time.sleep(THROTTLE_EVENT_LOOP_SEC)

            outer_end = time.time()
            outer_elapsed_time = outer_end - outer_start
            self.simple_log('## Outer event loop finished {} requests in {:.1f} seconds'.format(
                requests_processed, outer_elapsed_time), 2)
            self.simple_log('## which is {:.1f} requests per second'.format(requests_processed / outer_elapsed_time), 2)

        return records

    ################################################################################
    # API
    ################################################################################

    def get_public_resolvers(self, min_reliability, pub_ns_limit):

        def _reliability_filter(public_resolvers, min_reliability):

            # extract resolvers only with reliability > min_reliability
            reliable_resolvers = []
            for resolver in public_resolvers[1:]:
                if len(resolver) == 10:
                    _filter = [
                        float(resolver[7]) >= float(min_reliability),
                        DNSweeper.ipv4_validate(resolver[0])
                    ]
                    if all(_filter):
                        reliable_resolvers.append(resolver[0])

            self.simple_log('### {} public resolvers with reliability >= {}'.format(len(reliable_resolvers), min_reliability), 3)
            return reliable_resolvers

        # Param validation
        if not (0 <= float(min_reliability) <= 1):
            raise ValueError("Invalid min_reliability. Minimum reliability filter must be number between 0 and 1")

        # Parse
        self.simple_log('## Opening public resolvers source file: {}'.format(self.public_resolvers_local_source), 2)
        with open(self.public_resolvers_local_source, mode='r') as f:
            reader = csv.reader(f, delimiter=',')
            resolvers = list(reader)

        # Filtering
        resolvers = resolvers[:pub_ns_limit]
        self.simple_log('## All public resolvers: {}'.format(len(resolvers)), 2)
        public_reliable_resolvers = _reliability_filter(resolvers, min_reliability)

        return public_reliable_resolvers[:pub_ns_limit]

    def update_public_resolvers(self):

        self.simple_log('# Fetching data from {} ...'.format(self.public_resolvers_remote_source), 1)
        _data = requests.get(self.public_resolvers_remote_source)
        self.simple_log('# Writing data to {} ...'.format(self.public_resolvers_local_source), 1)
        with open(self.public_resolvers_local_source, mode='wb+') as f:
            f.write(_data.content)

    def combine_resolvers(self, testing_domain, min_reliability, pub_ns_limit):

        # Prepare public resolvers
        self.simple_log('# Fetching public resolvers...', 1)
        public_resolvers = self.get_public_resolvers(min_reliability, pub_ns_limit)

        # Query public and trusted resolvers in one event loop run
        all_resolvers = data.TRUSTED_RESOLVERS + public_resolvers
        self.simple_log('# Querying A records from trusted and public resolvers...', 1)
        all_resolvers_A_results = self._get_records(testing_domain, 'A', all_resolvers, sweep_mode='resolvers')

        self.simple_log('# Extracting A records from DNS answers...', 1)
        # Extract results for trusted and public resolvers
        trusted_resolvers_A_results = all_resolvers_A_results[:len(data.TRUSTED_RESOLVERS)]
        public_resolvers_A_results = all_resolvers_A_results[len(data.TRUSTED_RESOLVERS):]

        # Extract A records from trusted resolvers
        trusted_resolvers_A_records = self.extract_A_records(trusted_resolvers_A_results)
        trusted_ips = {ip for record in trusted_resolvers_A_records for ip in record['A']}
        self.simple_log('# A records from trusted resolvers: {}'.format(trusted_ips), 1)

        # Compare all public resolvers A records with A records from trusted resolvers
        # If matched then we have public verified resolver
        public_verified_resolvers = []
        for resolver in public_resolvers_A_results:
            if type(resolver['result']) is not aiodns.error.DNSError:
                A_records = set(DNSweeper.extract_A_record(resolver['result']))
                if A_records.issubset(trusted_ips):
                    public_verified_resolvers.append(resolver['ns'])
                else:
                    self.simple_log('# Resolver {} returned A records {} which are not in trusted resolvers A records'.
                                format(resolver['ns'], A_records), 1)

        # Merge public and trusted resolvers and remove duplicates.
        all_verified_resolvers = set(public_verified_resolvers + data.TRUSTED_RESOLVERS)

        self.simple_log('# Got {} verified and trusted public resolvers'.format(len(all_verified_resolvers)), 1)
        return all_verified_resolvers

    def garbage_query_filter(self, testing_name, resolvers):

        self.simple_log('# Starting garbage query filtering...', 1)
        resolvers = set(resolvers)

        # Filtering round 1
        random_string = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
        random_subdomain = random_string + '.' + '.'.join(testing_name.split('.')[-2:])
        self.simple_log('# Filtering out all valid responses to {}'.format(random_subdomain), 1)

        records = self._get_records(random_subdomain, 'A', resolvers, sweep_mode='resolvers')

        bad_resolvers = []
        for record in records:
            if type(record['result']) is not aiodns.error.DNSError:
                A_records = self.extract_A_record(record['result'])
                self.simple_log('## Resolver {} resolves {} to {}'.format(record['ns'], random_subdomain, A_records), 2)
                bad_resolvers.append(record['ns'])
        resolvers.difference_update(bad_resolvers)

        self.simple_log('# Removed {} bad resolvers'.format(len(bad_resolvers)), 1)

        # Filtering round 2
        if FILTER2ROUNDS:

            random_string1 = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
            random_string2 = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
            random_subdomain = random_string1 + '.' + random_string2 + '.'.join(testing_name.split('.')[-2:])
            self.simple_log('# Filtering out all valid responses to {}'.format(random_subdomain), 1)

            records = self._get_records(random_subdomain, 'A', resolvers, sweep_mode='resolvers')

            bad_resolvers = []
            for record in records:
                if type(record['result']) is not aiodns.error.DNSError:
                    A_records = self.extract_A_record(record['result'])
                    self.simple_log('## Resolver {} resolves {} to {}'.format(record['ns'], random_subdomain, A_records), 2)
                    bad_resolvers.append(record['ns'])
            resolvers.difference_update(bad_resolvers)

            self.simple_log('# Removed {} bad resolvers'.format(len(bad_resolvers)), 1)

        return resolvers

    def reverse_lookup(self, netblock, resolvers):

        iplist = self.netblock_to_iplist(netblock)
        self.simple_log('reverse_lookup: Sweeping {} IPs'.format(len(iplist)), 2)
        arpa_hosts = self.ip_to_arpa(iplist)
        resolvers_PTR_results = self._get_records(arpa_hosts, 'PTR', resolvers, sweep_mode='names')
        return self.extract_PTR_records(resolvers_PTR_results)

    def forward_lookup_fast(self, domains, resolvers):

        # Remove excluded subdomains
        self.simple_log('# Removing excluded subdomains...', 1)
        domains = self.remove_excluded_subdomains(domains, self.exclude_subdomains)

        self.simple_log('# Performing fast forward lookup for {} domains in {} resolvers...'.format(
            len(domains), len(resolvers)), 1)
        A_results = self._get_records(domains, 'A', resolvers, sweep_mode='names')
        A_records = self.extract_A_records(A_results)
        self.simple_log('# Found {} unique A records'.format(len(self.get_unique_A_records(A_records))), 1)
        return A_records

    def forward_lookup_full(self, domains, resolvers):

        def resolve(domain, resolvers):
            self.simple_log('## Performing forward lookup for {} in {} resolvers...'.format(domain, len(resolvers)), 2)
            A_results = self._get_records(domain, 'A', resolvers, sweep_mode='resolvers')
            A_records = self.extract_A_records(A_results)
            self.simple_log('## Found {} unique A records'.format(len(self.get_unique_A_records(A_records))), 2)
            return A_records

        # Remove excluded subdomains
        self.simple_log('# Removing excluded subdomains...', 1)
        domains = self.remove_excluded_subdomains(domains, self.exclude_subdomains)

        self.simple_log('# Performing full forward lookup for {} domains in {} resolvers...'.format(
            len(domains), len(resolvers)), 1)
        A_records_from_all_resolvers = []
        for subdomain in domains:
            A_recs = resolve(subdomain, resolvers)
            A_records_from_all_resolvers.append(
                {
                    'name': subdomain,
                    'A': self.get_unique_A_records(A_recs)
                }
            )

        return A_records_from_all_resolvers

    def bruteforce(self, domain, payload, resolvers):

        # Returns even subdomains with empty A records which means
        # that there exists dangling mapping subdomain -> CNAME -> empty A record
        complete_payload = ['{}.{}'.format(word, domain) for word in payload]
        self.simple_log('# Subdomains payload count: {}'.format(len(complete_payload)), 1)

        # Remove excluded subdomains
        self.simple_log('# Removing excluded subdomains...', 1)
        payload = self.remove_excluded_subdomains(complete_payload, self.exclude_subdomains)

        # Note here that bruteforce does --fast-sweep! First found A record is returned.
        resolvers_A_results = self._get_records(payload, 'A', resolvers, sweep_mode='names')
        res1 = self.extract_A_records(resolvers_A_results)

        # Additional filtering of results by trusted resolvers
        self.simple_log('# Performing fine filtering with trusted resolvers...', 1)
        names = self.extract_names(res1)
        self.simple_log('# Fine filtering {} subdomains'.format(len(names)), 1)
        res2 = self._get_records(names, 'A', data.TRUSTED_RESOLVERS, sweep_mode='names')
        res3 = self.extract_A_records(res2)
        self.simple_log('# Removed {} bad subdomains'.format(len(names) - len(res3)), 1)

        # Remove subdomains with empty A record (dangling CNAME records)
        self.simple_log('# Removing subdomains with empty A records...', 1)
        res4 = self.remove_empty_A_records(res3)
        self.simple_log('# Removed {} subdomains with empty A records'.format(len(res3) - len(res4)), 1)

        return res4

    def bruteforce_recursive(self, domains, payload, resolvers):

        for domain in domains:
            self.simple_log('# Performing recursive bruteforce on {}'.format(domain), 1)
            result = self.bruteforce(domain, payload, resolvers)
            domains.extend(self.extract_names(result))

    ################################################################################
    # HELPERS
    ################################################################################

    def netblock_to_iplist(self, netblock):

        if '-' in netblock:

            netblock = netblock.split('-')
            start_ip = ipaddress.IPv4Address(netblock[0])
            end_ip = ipaddress.IPv4Address(netblock[1])
            # end_ip must be included
            iplist = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]

        elif '/' in netblock:

            iplist = [str(ip) for ip in ipaddress.IPv4Network(netblock)]

        elif type(netblock) == list:

            for ip in netblock:
                if not self.ipv4_validate(ip):
                    raise ValueError('Invalid IPv4 format: {}'.format(ip))

            iplist = netblock

        else:

            print('>>> {} <<<'.format(netblock))
            raise ValueError('Invalid netblock format')

        return iplist

    def simple_log(self, text, verbosity):
        if self.args['verbosity'] >= verbosity:
            print(text)

    def set_args(self, args):
        self.args = vars(args)

    def asns_to_ips(self, asns):

        ip_list = []
        for asn_record in asns:
            ip_list.extend(self.netblock_to_iplist(asn_record['BGP Prefix']))

        return ip_list

    def filter_ptr_records(self, ptr_records):

        regexp = self.args['reverse_regex']

        self.simple_log('Filtering reverse lookup results with regexp: \'{}\''.format(regexp), 2)
        filtered_ptr_records = []
        for ptr_record in ptr_records:
            if re.search(regexp, ptr_record['name']):
                filtered_ptr_records.append(ptr_record)

        return filtered_ptr_records

    def ips_to_asn(self, ips):

        def query(bulk_query, timeout):
            """ Connects to the IPTOASN_API_URL whois server and sends the bulk query. Returns the
            result of this query.
            """

            data = ''
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:

                s.connect((IPTOASN_API_URL, IPTOASN_API_PORT))
                s.sendall(bulk_query.encode('utf-8'))
                reply = s.recv(4098)
                data = reply
                # Gets data until an empty line is found.
                while True:
                    reply = s.recv(1024)
                    data += reply

            except socket.timeout:

                if data != '':
                    pass
                else:
                    raise

            except Exception as e:
                raise e

            finally:
                s.close()

            return data

        def to_json(data):

            row_names = ["AS", "IP", "BGP Prefix", "CC", "Registry", "Allocated", "Info", "AS Name"]

            data_json = []
            for line in data.decode('utf-8').split('\n')[1:-1]:
                record_split = line.split('|')
                record_split = [col.strip() for col in record_split]
                data_json.append({
                    'AS': record_split[0],
                    'IP': record_split[1],
                    'BGP Prefix': record_split[2],
                    'CC': record_split[3],
                    'Registry': record_split[4],
                    'Allocated': record_split[5],
                    'Info': record_split[6],
                })

            return data_json


        ips = list(set(ips))
        for ip in ips:
            if not self.ipv4_validate(ip):
                raise ValueError('{} is not valid IP'.format(ip))

        self.simple_log('# Retrieving ASN records for {} IPs...'.format(len(ips)), 1)
        bulk_query = 'begin\nverbose\n{}\nend'.format('\n'.join(ips))
        response = query(bulk_query, AIODNS_TIMEOUT)
        response_json = to_json(response)

        return response_json

    def _check_tcp_limit(self):

        if platform.system() == 'Linux':

            (rlimit_nofile_soft, rlimit_nofile_hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
            self.simple_log('### Maximum number of opened file descriptors (Soft, Hard): {}, {}'.format(
                rlimit_nofile_soft, rlimit_nofile_hard), 3)

            if rlimit_nofile_soft < RLIMIT_NOFILE_TEMP:

                new_limit = RLIMIT_NOFILE_TEMP if RLIMIT_NOFILE_TEMP < rlimit_nofile_hard else rlimit_nofile_hard
                resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, rlimit_nofile_hard))
                self.simple_log('### Maximum number of opened file descriptors temporarily set to: {}'.format(
                    new_limit), 3)

        if platform.system() == 'Darwin':

            # Kernel limits
            kern_maxfilesperproc =  subprocess.check_output(["sysctl", "kern.maxfilesperproc"])
            kern_maxfilesperproc =  int(kern_maxfilesperproc.decode().rstrip().split(':')[1].strip())
            self.simple_log('### Maximum number of opened file descriptors by kernel: {}'.format(
                kern_maxfilesperproc), 3)

            # ulimit limits
            (rlimit_nofile_soft, rlimit_nofile_hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
            self.simple_log('### Maximum number of opened file descriptors by ulimit (Soft, Hard): {}, {}'.format(
                rlimit_nofile_soft, rlimit_nofile_hard), 3)


            if rlimit_nofile_soft < RLIMIT_NOFILE_TEMP:
                new_limit = RLIMIT_NOFILE_TEMP if RLIMIT_NOFILE_TEMP < kern_maxfilesperproc else kern_maxfilesperproc
                resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, new_limit))
                self.simple_log('### Maximum number of opened file descriptors temporarily set to: {}'.format(
                    new_limit), 3)
                if new_limit < 20000:
                    self.simple_log('Warning: maximum limit of opened file descriptors is low: {}'.format(new_limit), 0)
                    self.simple_log('It should be > 20000. Increase with: '.format(new_limit), 0)
                    self.simple_log('$ sudo sysctl -w kern.maxfiles=40000 '.format(new_limit), 0)
                    self.simple_log('$ sudo sysctl -w kern.maxfilesperproc=30000 '.format(new_limit), 0)

    def extract_PTR_records(self, resolvers_PTR_results):

        PTR_records = []
        for arpa_ip in resolvers_PTR_results:

            try:

                if type(arpa_ip['result']) is not aiodns.error.DNSError:

                    record = {
                        'ip': DNSweeper.arpa_to_ip(arpa_ip['name']),
                        'name': arpa_ip['result'].name
                    }
                    PTR_records.append(record)

            except UnicodeError:

                self.simple_log('### Unicode error in A records: {}'.format(arpa_ip), 3)

        return PTR_records

    def extract_A_records(self, resolvers_A_results):

        A_records = []
        for resolver in resolvers_A_results:

            try:

                if type(resolver['result']) is not aiodns.error.DNSError:
                    record = {
                        'name': resolver['name'],
                        'A': DNSweeper.extract_A_record(resolver['result'])
                    }
                    A_records.append(record)

            except UnicodeError:
                self.simple_log('### Unicode error in A records: {}'.format(resolver), 3)

        return A_records

    @staticmethod
    def remove_excluded_subdomains(subdomains, exclude):

        regexes = [re.compile(line.split('/')[1]) for line in exclude if 'R/' in line]
        strings = set(line for line in exclude if 'R/' not in line)

        # Regex filter
        filtered = set(
            subdomain for subdomain in subdomains if not any([regex.search(subdomain) for regex in regexes])
        )

        # Simple string filter
        filtered.difference_update(strings)

        return list(filtered)

    @staticmethod
    def remove_empty_A_records(records):
        return [record for record in records if record['A']]

    @staticmethod
    def get_uniq_asns(asn_records):

        # Filter uniq AS and filter out NA records. Warning: We are losing IPs here!
        return list({record['AS']:record for record in asn_records if record['AS'] != 'NA'}.values())

    @staticmethod
    def ipv4_validate(ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def arpa_to_ip(arpa):

        if '.in-addr.arpa' not in arpa:
            raise ValueError('Invalid reverse pointer format')

        ip = arpa.replace('.in-addr.arpa', '').split('.')
        ip.reverse()
        ip = '.'.join(ip)
        if not DNSweeper.ipv4_validate(ip):
            print('>>> {} <<<'.format(ip))
            raise ValueError('Invalid IPv4 address')

        return ip

    @staticmethod
    def ip_to_arpa(ips):

        if isinstance(ips, str):
            return ipaddress.ip_address(ips).reverse_pointer
        elif isinstance(ips, list):
            return [ipaddress.ip_address(ip).reverse_pointer for ip in ips]
        else:
            raise ValueError('Invalid input type. Valid types: list, str')

    @staticmethod
    def extract_A_record(resolvers_A_result):
        return [record.host for record in resolvers_A_result]

    @staticmethod
    def extract_names(A_records):

        out = []
        if A_records:
            out = list({result['name'] for result in A_records})

        return out

    @staticmethod
    def get_unique_A_records(A_records):
        return list({ip for record in A_records for ip in record['A']})


class App(object):

    def __init__(self):

        if not len(sys.argv) > 1:
            sys.exit('No parameters passed to DNSweeper.\n'
                     'Run DNSweeper.py -h for help')

        self.dnsw = DNSweeper()
        self.args = self.parse_args()
        self.dnsw.args.update(vars(self.args))
        if self.dnsw.args['exclude_file']:
            self.dnsw.exclude_subdomains = self.read_file(self.dnsw.args['exclude_file'])

        # Cache
        self.filtered_resolvers = []
        self.unique_ips = []
        self.bruteforce_result = []
        self.filtered_ptr_records = []

    def run_command(self):

        self.args.func()
        if self.dnsw.args['output_dir']:
            self.simple_log('See results in {}'.format(self.dnsw.args['output_dir']), 0)

    ################################################################################
    # COMMAND-LINE INTERFACE
    ################################################################################

    def parse_args(self):

        # Parent parser
        parent_parser = argparse.ArgumentParser(description="DNSsweeper - Asynchronous public DNS auditing tool")
        subparsers = parent_parser.add_subparsers(title='commands', help='Description')

        ################################################################################
        # enumerate command parser
        ################################################################################

        parser_enumerate = subparsers.add_parser('enumerate',
                                                 help='Perform complete enumeration',
                                                 description='enumerate command prepares filtered public resolvers for '
                                                             'given input domain. It performs bruteforce subdomain '
                                                             'discovery. Then it forward-lookup each subdomain in '
                                                             'all filtered resolvers and extracts corresponding ASN '
                                                             'netblocks. Next it performs reverse-lookup '
                                                             'in all IPs from discovered ASN netblocks and optionally '
                                                             'filters output with given REGEX.')
        parser_enumerate.set_defaults(func=self.enumerate)
        input_group = parser_enumerate.add_mutually_exclusive_group(required=True)
        input_group.add_argument('-f',
                                 metavar='FILE',
                                 help='Path to file with (scraped) subdomains',
                                 dest='file_input')
        input_group.add_argument('-d',
                                 metavar='DOMAIN',
                                 help='Domain (ie. test_domain.com)',
                                 dest='domain_input')
        parser_enumerate.add_argument('-p',
                                      metavar='FILE',
                                      help='Path to file with bruteforce payload',
                                      required=False,
                                      default=DEFAULT_BRUTEFORCE_PAYLOAD,
                                      dest='payload_file')
        parser_enumerate.add_argument('-r',
                                      metavar='REGEX',
                                      help='Reverse lookup regex matching pattern',
                                      required=False,
                                      dest='reverse_regex')
        parser_enumerate.add_argument('-o',
                                      metavar='DIR_PATH',
                                      help='Path to directory with results',
                                      required=False,
                                      default=DEFAULT_OUTPUT_DIR,
                                      dest='output_dir')
        parser_enumerate.add_argument('--use-cache',
                                      help='Use cached resolvers',
                                      required=False,
                                      default=False,
                                      action='store_true',
                                      dest='use_cache')
        parser_enumerate.add_argument('--fast-sweep',
                                      help='Don\'t sweep all resolvers. '
                                           'For every subdomain return just first valid resolver answer.',
                                      required=False,
                                      default=False,
                                      action='store_true',
                                      dest='fast_sweep')
        parser_enumerate.add_argument('--no-bruteforce',
                                      help='Don\'t use bruteforce command. ',
                                      required=False,
                                      default=False,
                                      action='store_true',
                                      dest='no_bruteforce')
        parser_enumerate.add_argument('--bruteforce-recursive',
                                      help='Enable recursive bruteforce. Path to payload file must be specified. '
                                           'Use smaller wordlists.',
                                      metavar='FILE',
                                      required=False,
                                      dest='bruteforce_recursive')
        parser_enumerate.add_argument('--exclude',
                                      help='File with subdomains which not to enumerate. (improves speed) ',
                                      metavar='FILE',
                                      required=False,
                                      dest='exclude_file')
        parser_enumerate.add_argument('-v',
                                      help='Verbosity, -v, -vv, -vvv',
                                      action='count',
                                      default=0,
                                      dest='verbosity')

        ################################################################################
        # resolvers command parser
        ################################################################################

        parser_resolvers = subparsers.add_parser('resolvers',
                                                 help='Output filtered resolvers',
                                                 description='resolvers command filters-out misconfigured or censored '
                                                             'public resolvers for given domain or subdomain and outputs '
                                                             'filtered resolvers into file.')
        parser_resolvers.set_defaults(func=self.get_filtered_resolvers)
        parser_resolvers.add_argument('-d',
                                      metavar='DOMAIN',
                                      help='Domain or subdomain which to validate public resolvers against',
                                      required=True,
                                      dest='domain_input')
        parser_resolvers.add_argument('-o',
                                      metavar='DIR_PATH',
                                      help='Path to directory with results',
                                      required=False,
                                      default=DEFAULT_OUTPUT_DIR,
                                      dest='output_dir')
        parser_resolvers.add_argument('-v',
                                      help='Verbosity, -v, -vv, -vvv',
                                      action='count',
                                      default=0,
                                      dest='verbosity')

        ################################################################################
        # bruteforce command parser
        ################################################################################

        parser_bruteforce = subparsers.add_parser('bruteforce',
                                                  help='Bruteforce subdomains',
                                                  description='bruteforce command performs bruteforce subdomain '
                                                              'discovery. It queries filtered public '
                                                              'resolvers. Particular query <-> resolver mappings are '
                                                              'permanently rotated - each new query is resolved with '
                                                              'different resolver. Payload is mangled with -i input.')
        parser_bruteforce.set_defaults(func=self.bruteforce)
        parser_bruteforce.add_argument('-d',
                                       metavar='DOMAIN',
                                       help='Domain or subdomain',
                                       required=True,
                                       dest='domain_input')
        parser_bruteforce.add_argument('-p',
                                       metavar='FILE',
                                       help='Path to file with bruteforce payload',
                                       required=False,
                                       default=DEFAULT_BRUTEFORCE_PAYLOAD,
                                       dest='payload_file')
        parser_bruteforce.add_argument('-o',
                                       metavar='DIR_PATH',
                                       help='Path to directory with results',
                                       required=False,
                                       default=DEFAULT_OUTPUT_DIR,
                                       dest='output_dir')
        parser_bruteforce.add_argument('--use-cache',
                                       help='Use cached resolvers',
                                       required=False,
                                       default=False,
                                       action='store_true',
                                       dest='use_cache')
        parser_bruteforce.add_argument('--bruteforce-recursive',
                                       help='Enable recursive bruteforce. Path to payload file must be specified. '
                                            'Use smaller wordlists.',
                                       metavar='FILE',
                                       required=False,
                                       dest='bruteforce_recursive')
        parser_bruteforce.add_argument('-v',
                                       help='Verbosity, -v, -vv, -vvv',
                                       action='count',
                                       default=0,
                                       dest='verbosity')


        ################################################################################
        # forward_lookup command parser
        ################################################################################

        parser_forward_lookup = subparsers.add_parser('forward_lookup',
                                                      help='Perform forward lookup',
                                                      description='forward_lookup command searches filtered '
                                                                  'resolvers for A records.')
        parser_forward_lookup.set_defaults(func=self.forward_lookup)
        parser_forward_lookup.add_argument('-f',
                                           metavar='FILE',
                                           help='Path to file with subdomains',
                                           required=True,
                                           dest='file_input')
        parser_forward_lookup.add_argument('-o',
                                           metavar='DIR_PATH',
                                           help='Path to directory with results',
                                           required=False,
                                           default=DEFAULT_OUTPUT_DIR,
                                           dest='output_dir')
        parser_forward_lookup.add_argument('-v',
                                           help='Verbosity, -v, -vv, -vvv',
                                           action='count',
                                           default=0,
                                           dest='verbosity')
        parser_forward_lookup.add_argument('--fast-sweep',
                                           help='Don\'t sweep all resolvers. '
                                                'For every subdomain return just first valid resolver answer.',
                                           required=False,
                                           default=False,
                                           action='store_true',
                                           dest='fast_sweep')
        parser_forward_lookup.add_argument('--use-cache',
                                           help='Use cached resolvers',
                                           required=False,
                                           default=False,
                                           action='store_true',
                                           dest='use_cache')
        parser_forward_lookup.add_argument('--exclude',
                                           help='File with subdomains which not to enumerate. (improves speed) ',
                                           metavar='FILE',
                                           required=False,
                                           dest='exclude_file')

        ################################################################################
        # asn_reverse_lookup command parser
        ################################################################################

        parser_asn_reverse_lookup = subparsers.add_parser('asn_reverse_lookup',
                                                          help='Perform ASN reverse lookup',
                                                          description='asn_reverse_lookup command performs '
                                                                      'forward-lookup for each subdomain in all '
                                                                      'filtered resolvers one-by-one. Obtained A '
                                                                      'records are then queried against ASN database '
                                                                      'and discovered netblocks are queried for PTR '
                                                                      'records.')
        parser_asn_reverse_lookup.set_defaults(func=self.asn_reverse_lookup)
        parser_asn_reverse_lookup.add_argument('-f',
                                               metavar='FILE',
                                               help='Path to file with IPs',
                                               required=True,
                                               dest='file_input')
        parser_asn_reverse_lookup.add_argument('-r',
                                               metavar='REGEX',
                                               help='Reverse lookup regex matching pattern',
                                               required=False,
                                               dest='reverse_regex')
        parser_asn_reverse_lookup.add_argument('-o',
                                               metavar='DIR_PATH',
                                               help='Path to directory with results',
                                               required=False,
                                               default=DEFAULT_OUTPUT_DIR,
                                               dest='output_dir')
        parser_asn_reverse_lookup.add_argument('-v',
                                               help='Verbosity, -v, -vv, -vvv',
                                               action='count',
                                               default=0,
                                               dest='verbosity')
        parser_asn_reverse_lookup.add_argument('--use-cache',
                                               help='Use cached resolvers',
                                               required=False,
                                               default=False,
                                               action='store_true',
                                               dest='use_cache')

        ################################################################################
        # update command parser
        ################################################################################

        parser_update_resolvers = subparsers.add_parser('update_resolvers',
                                                        help='Update raw resolver list',
                                                        description='update_resolvers command downloads fresh '
                                                                    'unfiltered public resolvers list')
        parser_update_resolvers.set_defaults(func=self.update_resolvers)
        parser_update_resolvers.add_argument('-v',
                                             help='Verbosity, -v, -vv, -vvv',
                                             action='count',
                                             default=0,
                                             dest='verbosity')

        return parent_parser.parse_args()

    ################################################################################
    # COMMANDS
    ################################################################################

    def get_filtered_resolvers(self):

        # Input
        domain_name = self.get_domain_name()

        # Get combined resolvers
        self.simple_log('Getting public resolvers which resolves {} reliably...'.format(domain_name), 0)
        combined_resolvers = self.dnsw.combine_resolvers(domain_name, MIN_RELIABILITY, PUB_NS_LIMIT)

        # Filter out resolvers which returns valid A answer to garbage A question
        self.simple_log('Filtering out bad resolvers...', 0)
        self.filtered_resolvers = self.dnsw.garbage_query_filter(domain_name, combined_resolvers)

        # Output
        file_name = os.path.join(self.dnsw.args['output_dir'], 'filtered_resolvers_result.json')
        self.write_file(file_name, self.filtered_resolvers)

        # Cache
        file_name = DEFAULT_CACHE_DIR + 'filtered_resolvers_cached.json'
        self.write_file(file_name, self.filtered_resolvers)

        self.simple_log('The \'resolvers\' command completed successfully!', 0)

    def bruteforce(self):

        self.simple_log('Bruteforcing subdomains...', 0)
        self.load_resolvers()

        domain_name = self.get_domain_name()
        self.simple_log('Loading payload...', 1)
        payload = self.read_file(self.dnsw.args['payload_file'])
        bruteforce_records = self.dnsw.bruteforce(domain_name, payload, self.filtered_resolvers)
        bruteforce_subdomains = self.dnsw.extract_names(bruteforce_records)

        if self.dnsw.args['bruteforce_recursive']:
            payload = self.read_file(self.dnsw.args['bruteforce_recursive'])
            self.dnsw.bruteforce_recursive(bruteforce_subdomains, payload, self.filtered_resolvers)

        # Output
        self.simple_log('Bruteforce discovered {} subdomains...'.format(len(bruteforce_subdomains)), 0)
        file_name = os.path.join(self.dnsw.args['output_dir'], 'bruteforce_result.json')
        self.write_file(file_name, bruteforce_subdomains)

        # Cache
        self.bruteforce_result = bruteforce_subdomains

        self.simple_log('The \'bruteforce\' command completed successfully!', 0)

    def forward_lookup(self):

        self.simple_log('Performing forward-lookup...', 0)
        self.load_resolvers()

        subdomains = []
        if self.dnsw.args['file_input']:
            subdomains = self.read_file(self.dnsw.args['file_input'])
        if self.bruteforce_result:
            self.simple_log('# Extending input with previously bruteforced subdomains...', 1)
            subdomains.extend(self.bruteforce_result)
            subdomains = list(set(subdomains))

        if self.dnsw.args['fast_sweep']:
            A_records = self.dnsw.forward_lookup_fast(subdomains, self.filtered_resolvers)
        else:
            A_records = self.dnsw.forward_lookup_full(subdomains, self.filtered_resolvers)

        # Output
        file_name = os.path.join(self.dnsw.args['output_dir'], 'forward_lookup_result.json')
        self.write_file(file_name, A_records)

        file_name = os.path.join(self.dnsw.args['output_dir'], 'forward_lookup_unique_ips.json')
        unique_ips = self.dnsw.get_unique_A_records(A_records)
        self.write_file(file_name, unique_ips)

        # Cache
        self.unique_ips = unique_ips

        self.simple_log('The \'forward_lookup\' command completed successfully!', 0)

    def asn_reverse_lookup(self):

        self.simple_log('Performing asn reverse-lookup...', 0)
        self.load_resolvers()

        if not self.unique_ips:
            self.unique_ips = self.read_file(self.dnsw.args['file_input'])

        asn_records = self.dnsw.ips_to_asn(self.unique_ips)
        unique_asns = self.dnsw.get_uniq_asns(asn_records)
        self.simple_log('Found {} unique ASNs'.format(len(unique_asns)), 0)

        reverse_lookup_ips = self.dnsw.asns_to_ips(unique_asns)

        self.simple_log('Performing reverse lookup for {} IPs'.format(len(reverse_lookup_ips)), 0)
        ptr_records = self.dnsw.reverse_lookup(reverse_lookup_ips, self.filtered_resolvers)

        if self.dnsw.args['reverse_regex']:
            self.filtered_ptr_records = self.dnsw.filter_ptr_records(ptr_records)
            regex = self.dnsw.args['reverse_regex']
            self.simple_log('Found {} subdomains matching regex {}'.format(len(self.filtered_ptr_records), regex), 0)
            file_name = os.path.join(self.dnsw.args['output_dir'], 'asn_reverse_lookup_regex_ptr.json')
            self.write_file(file_name, self.filtered_ptr_records)

        # Output
        file_name = os.path.join(self.dnsw.args['output_dir'], 'asn_reverse_lookup_asn.json')
        self.write_file(file_name, unique_asns)

        file_name = os.path.join(self.dnsw.args['output_dir'], 'asn_reverse_lookup_all_ptr.json')
        self.write_file(file_name, ptr_records, compress=True)

        self.simple_log('The \'asn_reverse_lookup\' command completed successfully!', 0)

    def enumerate(self):

        self.simple_log('Enumerating subdomains...', 0)
        self.load_resolvers()

        if not self.dnsw.args['no_bruteforce']:
            self.bruteforce()
        self.forward_lookup()
        self.asn_reverse_lookup()

        # Output unique subdomains
        file_name = os.path.join(self.dnsw.args['output_dir'], 'enumerate_unique_subdomains.json')
        uniq_subdomains = self.bruteforce_result + self.dnsw.extract_names(self.filtered_ptr_records)
        self.write_file(file_name, uniq_subdomains)

        self.simple_log('The \'enumerate\' command completed successfully!', 0)

    def update_resolvers(self):

        self.simple_log('Updating resolvers...', 0)
        self.dnsw.update_public_resolvers()
        self.simple_log('The \'update_resolvers\' command completed successfully!', 0)

    ################################################################################
    # HELPERS
    ################################################################################

    def load_resolvers(self):

        # If resolvers not loaded yet
        if not self.filtered_resolvers:
            # Use cached resolvers
            if self.dnsw.args['use_cache']:

                try:

                    self.filtered_resolvers = self.read_file(DEFAULT_CACHE_DIR + 'filtered_resolvers_cached.json')
                    self.simple_log('Using {} cached resolvers...'.format(len(self.filtered_resolvers)), 0)

                except IOError:

                    self.simple_log('Cached resolvers not ready yet. Gathering new resolvers...', 0)
                    self.get_filtered_resolvers()
                    return

            # Or filter and prepare fresh resolvers
            else:
                self.simple_log('Gathering new resolvers...', 0)
                self.get_filtered_resolvers()

        else:
            self.simple_log('# Resolvers already loaded...', 1)

    def get_domain_name(self):

        if self.dnsw.args['domain_input']:
            domain_name = self.dnsw.args['domain_input']
        elif self.dnsw.args['file_input']:
            with open(self.dnsw.args['file_input']) as f:
                domain_name = f.readline().strip('\n')
                domain_name = '.'.join(domain_name.split('.')[-2:])
        else:
            raise ValueError('domain_input or file_input missing')

        return domain_name

    def simple_log(self, text, verbosity):
        if self.args.verbosity >= verbosity:
            print(text)

    def write_file(self, file_name, _data, compress=False):

        # Dumps data into JSON file
        self.simple_log('# Writing output to {}'.format(file_name), 1)
        pathlib.Path(self.dnsw.args['output_dir']).mkdir(parents=True, exist_ok=True)
        pathlib.Path(DEFAULT_CACHE_DIR).mkdir(parents=True, exist_ok=True)

        with open(file_name, 'w') as f:

            if compress:
                f.write(json.dumps(list(_data), separators=(',', ':')))
            else:
                f.write(json.dumps(list(_data), indent=JSON_INDENT, separators=(',', ':')))

            f.write('\n')

    def read_file(self, file_name):

        with open(file_name) as f:
            line = f.readline()

        with open(file_name) as f:

            if '[' in line[:2]:
                self.simple_log('# Reading input from JSON file {}'.format(file_name), 1)
                return json.load(f)
            else:
                self.simple_log('# Reading input from text file {}'.format(file_name), 1)
                return [line.rstrip('\n') for line in f]


if __name__ == '__main__':

    app = App()
    app.run_command()
