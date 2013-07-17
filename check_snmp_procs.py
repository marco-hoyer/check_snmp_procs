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
processes_obsessed = []
processes_not_running = []
processes = {}
debug = 0

# exit with unknown message and exit code, if anything went wrong
def exitunknown():
	print "UNKNOWN: unable to get running processes"
	sys.exit(3)

# execute system-calls
def execute(executable, params):
	if isinstance(params, str):
		params = [params]
	command = [executable]
	command.extend(params)
	p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out = p.stdout.read()
	err = p.stderr.read()
	return p.wait(), out, err

# query target-host to get a list of key-value pairs
def snmpgetlist(oid):
        result = execute(command ,params + [oid])
        if result[0] == 0:
                retval = str(result[1]).split('\n')
                if len(retval) <= 2:
                        exitunknown()
                return retval
        else:
                exitunknown()

# convert raw list to dict of key-value pairs
def convertlist(raw_list):
	dict = {}
	for line in raw_list:
		if line:
			line = line.split('=')
			key = line[0].split('.')[-1].strip()
			value = line[1].strip().strip('"')
			if value:
				dict[key] = value
	return dict

# get a list of processes and their parameters
def getprocesses():
	hrSWRunNameList = convertlist(snmpgetlist(hrSWRunName_oid))
	hrSWRunParametersList = convertlist(snmpgetlist(hrSWRunParameters_oid))
	for key, value in hrSWRunParametersList.items():
		hrSWRunNameList[key] = hrSWRunNameList[key] + " " + value
	return hrSWRunNameList

# check if a given string matches the list of running processes
def checkrunning(searchstring):
        for process in processes.values():
                if process.startswith(searchstring):
                        return 1
        return 0

# parameter handling
parser = argparse.ArgumentParser()
parser.add_argument("--user", help="(if proto=v3) username", type=str)
parser.add_argument("--password", help="(if proto=v3) password", type=str)
parser.add_argument("hostname", help="hostname of system to query", type=str)
parser.add_argument("community", help="snmp community string",type=str)
parser.add_argument("protocol", help="snmp protocol version [1|2c|3]", type=str)
parser.add_argument("process_list", help="comma-separated list of processes", type=str)
args = parser.parse_args()

# create list of processes to search for
processes_obsessed = args.process_list.strip().split(',')

# create params list
params = ['-v' + args.protocol,'-Cr200','-Cn0','-OQns','-c' + args.community,args.hostname]
if args.protocol == '3':
	params.extend(['-lauthPriv', '-asha', '-xAES', '-u' + args.user, '-X' + args.password, '-A' + args.password])

# get a list of running processes
processes = getprocesses()

# check all processes needed to run
for item in processes_obsessed:
	if not checkrunning(item):
		processes_not_running.append(item)

if len(processes_not_running) == 0:
	print "OK: all processes running"
	sys.exit(0)
else:
	print "Critical: %s not running" % ", ".join(processes_not_running)
	sys.exit(2)
