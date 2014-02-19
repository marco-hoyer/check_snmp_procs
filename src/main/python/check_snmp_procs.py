#!/usr/bin/python

# simple check-script parsing running processes using default linux mib
# supports snmp v1,2c,3

import subprocess
import argparse
import sys

hrSWRunName_oid = ".1.3.6.1.2.1.25.4.2.1.2"
hrSWRunParameters_oid = ".1.3.6.1.2.1.25.4.2.1.5"
hrSWRunStatus_oid = ".1.3.6.1.2.1.25.4.2.1.7"
command = "snmpbulkwalk"
params = []
debug = 0
verbose = 0

# exit with unknown message and exit code, if anything went wrong
def exit_unknown(error_message):
    print "UNKNOWN: %s" % error_message
    sys.exit(3)

# execute system-calls
def execute(executable, params):
    if isinstance(params, str):
        params = [params]
    command = [executable]
    command.extend(params)
    if debug:
        print "- executing: %s" % " ".join(command)
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.stdout.read()
    err = p.stderr.read()
    return p.wait(), out, err

# query target-host to get a list of key-value pairs
def get_list_by_snmp(oid):
    global params
    result = execute(command, params + [oid])
    if result[0] == 0:
        retval = str(result[1]).split('\n')
        if debug:
            print "- received %i values via snmp" % len(retval)
        if verbose:
            print "received items: \n %s \n" % retval
            
        if len(retval) <= 2:
            exit_unknown("received invalid data via snmp for oid %s" % oid)
        return retval
    else:
        exit_unknown("something went wrong on getting data via snmp for oid %s" % oid)

# convert raw list to dict of key-value pairs
def convert_list_to_kv_dict(raw_list):
    dict = {}
    for line in raw_list:
        if line:
            # split linestring into key and value only at the first occurrence of "="
            line = line.split('=', 1)
            # separate line elements only if there are two of them
            if len(line) == 2:
                # separate last oid element as pid
                key = line[0].split('.')[-1].strip()
                # remove unwanted characters
                value = line[1].strip().strip('"')
                # if there is anything left in value, add it to the dict with pid as key
                if value:
                    dict[key] = value
    return dict

# get a list of processes and their parameters
def get_processes():
    hrSWRunNameList = convert_list_to_kv_dict(get_list_by_snmp(hrSWRunName_oid))
    hrSWRunParametersList = convert_list_to_kv_dict(get_list_by_snmp(hrSWRunParameters_oid))
    for key, value in hrSWRunParametersList.items():
        try:
            hrSWRunNameList[key] = hrSWRunNameList[key] + " " + value
        except KeyError:
            if debug:
                print "could not match parameter: %s to process with pid: %s, ignoring it!" % (value, key)
            pass
    if debug:
        print "- created processes list with %d items" % len(hrSWRunNameList)
    if verbose:
        print "list of running processes: \n %s \n" % hrSWRunNameList
    return hrSWRunNameList

# check if a given string matches the list of running processes
def check_running(processes, searchstring):
    if not searchstring.strip():
        if debug:
            print "- found empty searchstring, skipping search!"
        return False
    for process in processes.values():
        if process.strip().startswith(searchstring.strip()):
            if debug:
                print "- found match for process: %s and searchstring: %s" % (process, searchstring)
            return True
    return False

# split a string with csv values into a list of values
def create_list_from_csv(string):
    return string.strip().split(',')

# main action
def main(args):
    global debug
    global verbose
    global params
    # check if debug or verbose option is set
    if args.debug:
        print "debug mode on"
        debug = True
    if args.verbose:
        print "verbose mode on"
        verbose = True

    # check if the correct snmp protocol version is given
    if not args.protocol in ["1", "2c", "3"]:
        exit_unknown("invalid protocol parameter supplied, use: 1|2c|3")

    # create list of processes to search for
    processes_obsessed = create_list_from_csv(args.process_list)
    if debug:
        print "processes to search for: %s" % processes_obsessed

    # create params list
    params = ['-v' + args.protocol, '-Cr200', '-Cn0', '-OQns', '-c' + args.community, args.hostname]
    if args.protocol == '3':
        try:
            # append params for snmpv3 auth and encryption
            params.extend(
                ['-lauthPriv', '-asha', '-xAES', '-u' + args.user, '-X' + args.password, '-A' + args.password])
        except TypeError:
            exit_unknown("not all parameters given for snmp v3, define --user and --password")

    # get list of running processes
    processes = get_processes()

    # check all processes needed to run
    processes_not_running = []
    for item in processes_obsessed:
        if item:
            if not check_running(processes, item):
                processes_not_running.append(item)

    if len(processes_not_running) == 0:
        print "OK: all processes running"
        sys.exit(0)
    else:
        print "Critical: %s not running" % ", ".join(processes_not_running)
        sys.exit(2)

# parameter handling separation
if __name__ == '__main__':
    # parameter handling
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="show debug output", action="store_true")
    parser.add_argument("--verbose", help="show verbose output", action="store_true")
    parser.add_argument("--user", help="(if proto=v3) username", type=str)
    parser.add_argument("--password", help="(if proto=v3) password", type=str)
    parser.add_argument("hostname", help="hostname of system to query", type=str)
    parser.add_argument("community", help="snmp community string", type=str)
    parser.add_argument("protocol", help="snmp protocol version [1|2c|3]", type=str)
    parser.add_argument("process_list", help="comma-separated list of processes", type=str)
    args = parser.parse_args()
    main(args)
