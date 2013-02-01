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




import requests
import urllib

from requests.auth import HTTPBasicAuth

from alertlogic.appliance import AlertLogicAppliance
from alertlogic.host import AlertLogicHost



class AlertLogicConnection(object):

    def __init__(self, access_token, secret_key, domain):
        self.access_token = access_token
        self.secret_key = secret_key
        self.base_url = 'https://%s/api' % domain
        self.accept_header = {'Accept': 'application/json'}


    def __repr__(self):
        return "Connection:%s" % self.base_url


    def _add_auth(self):
        return HTTPBasicAuth(self.access_token,self.secret_key)


    def _AlertLogic_get(self, path):
        url = '%s/%s' % (self.base_url, path)
        response = requests.get(url, auth=self._add_auth(), headers=self.accept_header)
        return response


    def _AlertLogic_put(self, path, put_data):
        url = '%s/%s' % (self.base_url, path)
        # Using tuples instead of dictionary for data so we must encode into a string
        data = urllib.urlencode(put_data)
        headers = self.accept_header
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = requests.put(url,
            auth=self._add_auth(),
            headers=headers,
            data=data)
        return response

    def _AlertLogic_put_params(self, path, params):
        url = '%s/%s' % (self.base_url, path)
        headers = self.accept_header
        headers['Content-Length'] = '0'
        response = requests.put(url, auth=self._add_auth(), headers=headers, params=params)
        return response


    def _AlertLogic_delete(self, path, put_data=None):
        url = '%s/%s' % (self.base_url, path)
        if put_data:
            data = urllib.urlencode(put_data)
            response = requests.delete(url,
                auth=self._add_auth(),
                headers=self.accept_header,
                data=data)
        else:
            response = requests.delete(url,
                auth=self._add_auth(),
                headers=self.accept_header)
        return response


    def list_appliances(self):
        cloud_appliances = self.get_all_appliances()
        appliance_list = [i.appliance_id for i in cloud_appliances]
        return appliance_list


    def get_all_appliances(self, appliance_ids=None):
        path = 'latest/appliance'
        response = self._AlertLogic_get(path)
        json = response.json()
        appliances = []
        if appliance_ids:
            for appliance_id in appliance_ids:
                appliances += [AlertLogicAppliance(j) for j in json if j['appliance_id'] == appliance_id]
        else:
            appliances += [AlertLogicAppliance(j) for j in json]
        return appliances


    def get_appliance(self, appliance_id):
        path = 'latest/appliance/%s' % appliance_id
        response = self._AlertLogic_get(path)
        appliance = AlertLogicAppliance(response.json())
        return appliance


    def delete_appliance(self, appliance):
        path = 'latest/appliance/%s' % appliance.appliance_id
        response = self._AlertLogic_delete(path)
        return response


    def list_hosts(self):
        hosts = self.get_all_hosts()
        host_list = [i.host_id for i in hosts]
        return host_list


    def get_all_hosts(self, host_ids=None):
        path = 'latest/host'
        response = self._AlertLogic_get(path)
        json = response.json()
        hosts = []
        if host_ids:
            for host_id in host_ids:
                hosts += [AlertLogicHost(j) for j in json if j['host_id'] == host_id]
        else:
            hosts += [AlertLogicHost(j) for j in json]
        return hosts


    def get_host(self, host_id):
        path = 'latest/host/%s' % host_id
        response = self._AlertLogic_get(path)
        host = AlertLogicHost(response.json())
        return host


    def delete_host(self, host):
        path = 'latest/host/%s' % host.host_id
        response = self._AlertLogic_delete(path)
        return response


    def add_host_to_appliance(self, host, appliance):
        path = 'latest/appliance/assign'
        put_data = {'appliance_id': appliance.appliance_id, 'host_id': host.host_id}
        response = self._AlertLogic_put(path, put_data)
        return response


    def add_hosts_to_appliance(self, hosts, appliance):
        path = 'latest/appliance/assign'
        put_data = [('appliance_id',appliance.appliance_id,)]
        for host in hosts:
            put_data.append(('host_id',host.host_id,))
        response = self._AlertLogic_put(path, put_data)
        return response


    def add_tag_to_host(self, host, tag_name, tag_value):
        path = 'latest/host/tag/%s' % host.host_id
        put_data = {'name': tag_name, 'value': tag_value}
        response = self._AlertLogic_put(path, put_data)
        return response

    def delete_tag_from_host(self, host, tag_name):
        path = 'latest/host/tag/%s' % host.host_id
        put_data = {'name': tag_name}
        response = self._AlertLogic_delete(path, put_data)
        return response

    def claim_appliance(self, instance_id, zone):
        path = 'latest/appliance/claim'
        payload = {'instance_id':instance_id,'zone':zone}
        response = self._AlertLogic_put_params(path,payload)
        return response