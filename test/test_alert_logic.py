# Author: Joseph Lawson <joe@joekiller.com>
# Copyright 2012 Joseph Lawson.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from alertlogic import *

class AlertLogicApiTester(unittest.TestCase):

    def setUp(self):
        print('setUp AlertLogicApiTester')
        self.access_token = ''
        self.secret_key = ''
        self.domain = 'cloud.alertlogic.com'
        self.appliance_id = ''
        self.appliance_instance_id = ''
        self.appliance_zone = ''
        self.host_id = ''
        self.host_id_2 = ''
        self.host_ids = [self.host_id,self.host_id_2]
        self.connection = AlertLogicConnection(self.access_token,self.secret_key,self.domain)
        print('Using connection %s.' % connection)

class GetAppliances(AlertLogicApiTester):
    def runTest(self):
        print('Trying to get all appliances.')
        appliances = self.connection.get_all_appliances()
        for appliance in appliances:
            print('Got appliance: %s with instance id: %s' % (appliance.appliance_id, appliance.instance_id))
        assert True

class GetHosts(AlertLogicApiTester):
    def runTest(self):
        print('Trying to get all hosts.')
        hosts = self.connection.get_all_hosts()
        for host in hosts:
            print('Got host: %s with instance id: %s' %(host.host_id, host.instance_id))
        assert True

class AssignHost(AlertLogicApiTester):
    def runTest(self):
        appliance = self.connection.get_appliance(self.appliance_id)
        host = self.connection.get_host(self.host_id)
        print('Trying to assign %s to %s.' %(appliance, host))
        result = self.connection.add_host_to_appliance(host,appliance)
        print('Result:')
        print('%s' % result)
        assert True

class AssignHosts(AlertLogicApiTester):
    def runTest(self):
        appliance = self.connection.get_appliance(self.appliance_id)
        hosts = self.connection.get_all_hosts(self.host_ids)
        print('Trying to assign %s to %s.' %(appliance, hosts))
        result = self.connection.add_hosts_to_appliance(hosts,appliance)
        print('Result: %s' % result)
        assert True

class AddAndRemoveTag(AlertLogicApiTester):
    def runTest(self):
        host = self.connection.get_host(self.host_id)
        tag_result = self.connection.add_tag_to_host(host,'test_name','test_value')
        host = self.connection.get_host(self.host_id)
        print('Result: %s %s' % (tag_result,host.tags))
        tag_result = self.connection.delete_tag_from_host(host,'test_name')
        host = self.connection.get_host(self.host_id)
        print('Result: %s %s' % (tag_result,host.tags))
        assert True

class ClaimAppliance(AlertLogicApiTester):
    def runTest(self):
        instance_id = self.appliance_instance_id
        instance_zone = self.appliance_zone
        appliance_id = self.connection.claim_appliance(instance_id,instance_zone)
        print('Result: %s id: %s' % (appliance_id,appliance_id.json))
        assert True