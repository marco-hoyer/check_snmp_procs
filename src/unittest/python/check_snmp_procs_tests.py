import unittest

import check_snmp_procs

class check_snmp_procs_test (unittest.TestCase):

	def test_execute(self):
		self.assertEqual(check_snmp_procs.execute("echo",['Hallo Welt']), (0, 'Hallo Welt\n', ''))
		self.assertEqual(check_snmp_procs.execute("echo",['Hallo','Welt','test','1','2','3']), (0, 'Hallo Welt test 1 2 3\n', ''))
		self.assertEqual(check_snmp_procs.execute("echo",[]), (0, '\n', ''))

	def test_create_list_from_csv(self):
		self.assertEqual(check_snmp_procs.create_list_from_csv("httpd"),['httpd'])
		self.assertEqual(check_snmp_procs.create_list_from_csv("httpd,crond,sshd,ntpd"),['httpd','crond','sshd','ntpd'])
		self.assertEqual(check_snmp_procs.create_list_from_csv("a"),['a'])
		self.assertEqual(check_snmp_procs.create_list_from_csv(""),[''])
		self.assertEqual(check_snmp_procs.create_list_from_csv("qmgr -l -t fifo -u,/sbin/dhclient -H devmho01 -q -cf /etc/dhcp/dhclient-eth0.conf -lf /var/lib/dhclient/dhclient-eth0.leases -pf /var/run/dhclient-eth0.pid eth0"),['qmgr -l -t fifo -u','/sbin/dhclient -H devmho01 -q -cf /etc/dhcp/dhclient-eth0.conf -lf /var/lib/dhclient/dhclient-eth0.leases -pf /var/run/dhclient-eth0.pid eth0'])
		self.assertEqual(check_snmp_procs.create_list_from_csv("[ext4-dio-unwrit]"),['[ext4-dio-unwrit]'])
		
	def test_check_running(self):
		processes = {'4167': 'vmtoolsd', '1141': 'nslcd', '2349': 'httpd -DRunAsApache','4235': 'ntpd -u ntp:ntp -p /var/run/ntpd.pid -g -x','16321': 'snmpd -LS0-6d -Lf /dev/null -p /var/run/snmpd.pid','3951': 'automount --pid-file /var/run/autofs.pid','3877': 'acpid','7637': 'qmgr -l -t fifo -u'}
		self.assertTrue(check_snmp_procs.check_running(processes,"vmtoolsd"))
		self.assertTrue(check_snmp_procs.check_running(processes," vmtoolsd "))
		self.assertTrue(check_snmp_procs.check_running(processes,"ntpd -u ntp:ntp -p /var/run/ntpd.pid -g -x"))
		self.assertTrue(check_snmp_procs.check_running(processes,"ntpd -u ntp:ntp"))
		self.assertTrue(check_snmp_procs.check_running(processes,"ntpd"))
		self.assertFalse(check_snmp_procs.check_running(processes,"ntp -u ntp:ntp"))
		self.assertFalse(check_snmp_procs.check_running(processes,"  "))

	def test_convert_list_to_kv_dict(self):
		input = ['hrSWRunName.1 = "init"', 'hrSWRunName.2 = "kthreadd"']
		output = {'1': 'init', '2': 'kthreadd'}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

	def test_convert_list_to_kv_dict_with_empty_list(self):
		input = []
		output = {}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

	def test_convert_list_to_kv_dict_with_missing_separator(self):
		input = ['hrSWRunParameters.1 ']
		output = {}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

	def test_convert_list_to_kv_dict_with_empty_value(self):
		input = ['hrSWRunParameters.32 = ""']
		output = {}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

	def test_convert_list_to_kv_dict_with_none_value(self):
		input = ['hrSWRunParameters.32 =']
		output = {}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

	def test_convert_list_to_kv_dict_with_multiple_dividers(self):
		input = ['hrSWRunParameters.1 = "carbon-cache.py bin/carbon-cache.py --instance=a start"']
		output = {'1': 'carbon-cache.py bin/carbon-cache.py --instance=a start'}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

	def test_convert_list_to_kv_dict_with_empty_list(self):
		input = []
		output = {}
		self.assertEqual(check_snmp_procs.convert_list_to_kv_dict(input),output)

