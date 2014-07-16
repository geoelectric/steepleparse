#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Parses the Steeplechase log"""

import dateutil.parser
import re
import json
import sys


_anomalies = []

REGEXPS = {
    'blank': r'steeplechase INFO\s*\|\s*$',
    'client start': r'.*Log output for (.*):',
    'client end': r'.*<<<<<<<',
    'sc error': r'steeplechase ERROR',
    'session start': r'.*Run step: INTERVAL_COMMAND',
    'stats block': r'.*STATS \((.*)\):',
    'test failure': r'.*{"action":"test_unexpected_fail"',
    'test result': r'.*{"action":"(test\w*)"',
    'test finished': r'.*Test finished',
    'total passed': r'.*Passed: (\d*)',
    'total failed': r'.*Failed: (\d*)',
}

for key in REGEXPS:
    REGEXPS[key] = re.compile(REGEXPS[key])


class Client_Early_Exit_Error(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def log_anomaly(number, line):
    _anomalies.append((number, line))


def check_for_anomalies(number, line):
    if REGEXPS["sc error"].match(line):
        log_anomaly(number, line)


def line_reader(filename):
    number = 0
    with open(filename, "r") as f:
        for line in f:
            number += 1
            check_for_anomalies(number, line)

            # Keep requeuing the line as long as send(True) is called
            while 1:
                repeat = yield number, line.strip()

                # received a next(), move on
                if not repeat:
                    break

                # received a send(True)
                while repeat:
                    repeat = yield None

    raise StopIteration(number)


def requeue_line(reader):
    reader.send(True)


def create_results():
    return {
        'clients': [],
        'session runtime': None,
        'total passed': None,
        'total failed': None,
        'anomalies': [],
    }


def create_client_results():
    return {
        'name': None,
        'blocks': None,
        'session runtime': None,
        'longest pass': None,
        'setup failures': [],
        'cleanup failures': [],
        'session failures': [],
        'failed blocks': [],
    }


def process_log(reader, results):
    process_steeplechase_setup(reader, results)
    process_client(reader, results)
    process_client(reader, results)
    process_steeplechase_cleanup(reader, results)


def process_steeplechase_setup(reader, results):
    for number, line in reader:
        if REGEXPS["client start"].match(line):
            requeue_line(reader)
            return


def process_client(reader, results):
    client_results = create_client_results()
    results['clients'].append(client_results)

    number, line = reader.next()
    m = REGEXPS['client start'].match(line)
    client_name = m.group(1)
    client_results['name'] = client_name

    try:
        process_client_setup(reader, client_results)
        process_client_session(reader, client_results)
        process_client_cleanup(reader, client_results)
    except Client_Early_Exit_Error as err:
        log_anomaly(err.value, '%(name)s exited early' %
                    {'name': client_name})


def process_client_setup(reader, client_results):
    while 1:
        number, line = reader.next()

        if REGEXPS['client end'].match(line):
            raise Client_Early_Exit_Error(number)

        if REGEXPS['test failure'].match(line):
            client_results['setup failures'].append((number, line))

        if REGEXPS['session start'].match(line):
            requeue_line(reader)
            break


def process_client_session(reader, client_results):
    client_results['blocks'] = 0
    first_dt = None
    last_dt = None
    pass_start_dt = None
    longest_pass_delta = None

    try:
        while 1:
            number, line = reader.next()

            if REGEXPS['client end'].match(line):
                raise Client_Early_Exit_Error(number)

            if REGEXPS['test finished'].match(line):
                break

            if REGEXPS['stats block'].match(line):
                requeue_line(reader)
                client_results['blocks'] += 1
                timestamp, passed = process_stats_block(reader, client_results)

                dt = dateutil.parser.parse(timestamp)
                # runtime
                if not first_dt:
                    first_dt = dt
                last_dt = dt

                # longest pass
                if passed:
                    if not pass_start_dt:
                        # start counting
                        pass_start_dt = dt
                    else:
                        # keep a running count
                        pass_delta = dt - pass_start_dt
                        if longest_pass_delta is None:
                            longest_pass_delta = pass_delta
                        else:
                            longest_pass_delta = max(pass_delta,
                                                     longest_pass_delta)
                else:
                    # reset
                    pass_start_dt = None

            if REGEXPS['test failure'].match(line):
                client_results['session failures'].append((number, line))
    finally:
        if longest_pass_delta:
            client_results[
                'longest pass'] = int(longest_pass_delta.total_seconds())
        if last_dt and first_dt:
            client_results['session runtime'] = int((
                last_dt - first_dt).total_seconds())


def process_stats_block(reader, client_results, just_scan=False):
    block = {}

    # header
    number, line = reader.next()
    m = REGEXPS['stats block'].match(line)
    block['timestamp'] = m.group(1)
    block['failed tests'] = []

    # Stats list + blank lines
    in_blank = False
    while 1:
        number, line = reader.next()

        if REGEXPS['blank'].match(line):
            in_blank = True
        elif in_blank:
            requeue_line(reader)
            break

    # test results
    while 1:
        number, line = reader.next()

        m = REGEXPS['test result'].match(line)
        if m:
            if m.group(1) != 'test_pass':
                block['failed tests'].append((number, line))
        else:
            requeue_line(reader)
            break

    if block['failed tests'] and not just_scan:
        client_results['failed blocks'].append(block)

    return block['timestamp'], not block['failed tests']


def process_client_cleanup(reader, client_results):
    while 1:
        number, line = reader.next()

        if REGEXPS['client end'].match(line):
            break

        if REGEXPS['stats block'].match(line):
            log_anomaly(number, '%(name)s got stats after test finished' % {
                'name': client_results['name']})
            requeue_line(reader)
            process_stats_block(reader, client_results, just_scan=True)

        if REGEXPS['test failure'].match(line):
            client_results['cleanup failures'].append((number, line))


def process_steeplechase_cleanup(reader, results):
    number, line = reader.next()

    number, line = reader.next()
    m = REGEXPS['total passed'].match(line)
    results['total passed'] = int(m.group(1))

    number, line = reader.next()
    m = REGEXPS['total failed'].match(line)
    results['total failed'] = int(m.group(1))

    # scan past the rest to let the reader check for anomalies
    for number, line in reader:
        pass


def parse(filename):
    reader = line_reader(filename)
    results = create_results()

    try:
        process_log(reader, results)
    except StopIteration as err:
        log_anomaly(err.args[0], 'Reached unexpected EOF')

    # Runtime == both clients up
    results['session runtime'] = min(results['clients'][0]['session runtime'],
                                     results['clients'][1]['session runtime'])

    results['anomalies'] = _anomalies
    return results


def main():
    print json.dumps(parse(sys.argv[1]), indent=4, sort_keys=True)


if __name__ == '__main__':
    main()
