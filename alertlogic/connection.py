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

    def __init__(self, access_token, secret_key, domain, cid=None):
        self.access_token = access_token
        self.secret_key = secret_key
        if cid:
            self.base_url = "https://%s/api/tm/v1/%s/" % (domain, cid)
        else:
            self.base_url = "https://%s/api/tm/v1/" % domain
        self.accept_header = {'Accept': 'application/json'}


    def __repr__(self):
        return "Connection:%s" % self.base_url


    def _add_auth(self):
        return HTTPBasicAuth(self.access_token,self.secret_key)


    def _AlertLogic_get(self, path, params=None):
        url = '%s/%s' % (self.base_url, path)
        headers=self.accept_header
        headers['Content-Length'] = '0'
        if params:
            response = requests.get(url,
                                    auth=self._add_auth(),
                                    headers=self.accept_header,
                                    params=params)
        else:
            response = requests.get(url,
                                    auth=self._add_auth(),
                                    headers=self.accept_header)
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

    def _AlertLogic_post(self, path, post_data):
        url = '%s/%s' % (self.base_url, path)
        # Using tuples instead of dictionary for data so we must encode into a string
        data = urllib.urlencode(post_data)
        headers = self.accept_header
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = requests.post(url,
                                auth=self._add_auth(),
                                headers=headers,
                                data=data)
        return response

    def _AlertLogic_put_params(self, path, params):
        url = '%s/%s' % (self.base_url, path)
        headers = self.accept_header
        headers['Content-Length'] = '0'
        response = requests.put(url,
                                auth=self._add_auth(),
                                headers=headers,
                                params=params)
        return response


    def _AlertLogic_post_params(self, path, post_data, params):
        url = '%s/%s' % (self.base_url, path)
        data = urllib.urlencode(post_data)
        headers = self.accept_header
        headers['Content-Length'] = '0'
        response = requests.put(url,
                                auth=self._add_auth(),
                                headers=headers,
                                params=params,
                                data=data)
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


    def list_appliances(self,
                        config_time_zone=None,
                        appliance_id=None,
                        metadata_hostname=None,
                        metadata_local_ipv4=None,
                        metadata_local_ipv6=None,
                        metadata_public_ipv4=None,
                        metadata_public_ipv6=None,
                        metadata_os_details=None,
                        metadata_os_type=None,
                        name=None,
                        searche=None,
                        status_details=None,
                        status_status=None,
                        tags=None):
        cloud_appliances = self.get_all_appliances(config_time_zone=config_time_zone,
                                                   appliance_id=appliance_id,
                                                   metadata_hostname=metadata_hostname,
                                                   metadata_local_ipv4=metadata_local_ipv4,
                                                   metadata_local_ipv6=metadata_local_ipv6,
                                                   metadata_public_ipv4=metadata_public_ipv4,
                                                   metadata_public_ipv6=metadata_public_ipv6,
                                                   metadata_os_details=metadata_os_details,
                                                   metadata_os_type=metadata_os_type,
                                                   name=name,
                                                   search=searche,
                                                   status_details=status_details,
                                                   status_status=status_status,
                                                   tags=tags)
        appliance_list = [i.appliance_id for i in cloud_appliances]
        return appliance_list


    def get_all_appliances(self,
                           config_time_zone=None,
                           appliance_id=None,
                           metadata_hostname=None,
                           metadata_local_ipv4=None,
                           metadata_local_ipv6=None,
                           metadata_public_ipv4=None,
                           metadata_public_ipv6=None,
                           metadata_os_details=None,
                           metadata_os_type=None,
                           name=None,
                           search=None,
                           status_details=None,
                           status_status=None,
                           tags=None):
        path = 'appliances'
        get_parameters = dict()
        if config_time_zone:
            get_parameters.append(('config.time_zone',config_time_zone,))
        if appliance_id:
            get_parameters.append(('id',appliance_id,))
        if metadata_hostname:
            get_parameters.append(('metadata.hostname',metadata_hostname,))
        if metadata_local_ipv4:
            get_parameters.append(('metadata.local_ipv4',metadata_local_ipv4,))
        if metadata_local_ipv6:
            get_parameters.append(('metadata.local_ipv6',metadata_local_ipv6,))
        if metadata_public_ipv4:
            get_parameters.append(('metadata.public_ipv4',metadata_public_ipv4,))
        if metadata_public_ipv6:
            get_parameters.append(('metadata.public_ipv6',metadata_public_ipv6,))
        if metadata_os_details:
            get_parameters.append(('metadata.os_details',metadata_os_details,))
        if metadata_os_type:
            get_parameters.append(('metadata.os_type',metadata_os_type,))
        if name:
            get_parameters.append(('name',name,))
        if search:
            get_parameters.append(('search',search,))
        if status_details:
            get_parameters.append(('status.details',status_details,))
        if status_status:
            get_parameters.append(('status.status',status_status,))
        if tags:
            get_parameters.append(('tags',tags,))
        if len(get_parameters):
            response = self._AlertLogic_get(path, get_parameters)
        else:
            response = self._AlertLogic_get(path)
        json = response.json()
        appliances = []
        if appliance_id:
            for appliance_id in appliance_id:
                appliances += [AlertLogicAppliance(j) for j in json if j['appliance_id'] == appliance_id]
        else:
            appliances += [AlertLogicAppliance(j) for j in json]
        return appliances

    def get_appliance(self, appliance_id):
        return self.retrieve_appliance(appliance_id=appliance_id)

    def retrieve_appliance(self, appliance_id):
        path = 'appliances/%s' % appliance_id
        response = self._AlertLogic_get(path)
        appliance = AlertLogicAppliance(response.json())
        return appliance

    def edit_appliance(self, appliance):
        path = 'appliances/%s' % appliance.appliance_id
        post_data = {'appliance': {'name': appliance.name}}
        if 'tags' in appliance:
            tag_list = list()
            for tag in appliance.tags:
                tag_list.append({'name': tag})
            post_data['appliance']['tags'] = tag_list

        response = self._AlertLogic_post(path, post_data)
        return response

    def replace_appliance(self, appliance_id, appliance_name, tags=None):
        path = 'appliances/%s' % appliance_id
        put_data = {'appliance': {'name': appliance_name}}
        if tags:
            tag_list = list()
            for tag in tags:
                tag_list.append({'name': tag})
            put_data['appliance']['tags'] = tag_list

        response = self._AlertLogic_put(path, put_data)
        return response


    def list_policies(self,
                      appliance_assignment_appliances=None,
                      default=None,
                      id=None,
                      name=None,
                      search=None,
                      tags=None,
                      tmhost_compress=None,
                      tmhost_encrypt=None,
                      tmhost_packet_size=None,
                      tmhost_udp=None,
                      type=None):
        path = 'policies'
        get_parameters = list()
        if appliance_assignment_appliances:
            get_parameters.append(('appliance_assignment.appliances',appliance_assignment_appliances,))
        if not default is None:
            get_parameters.append(('default',default,))
        if metadata_hostname:
            get_parameters.append(('metadata.hostname',metadata_hostname,))
        if metadata_local_ipv4:
            get_parameters.append(('metadata.local_ipv4',metadata_local_ipv4,))
        if metadata_local_ipv6:
            get_parameters.append(('metadata.local_ipv6',metadata_local_ipv6,))
        if metadata_public_ipv4:
            get_parameters.append(('metadata.public_ipv4',metadata_public_ipv4,))
        if metadata_public_ipv6:
            get_parameters.append(('metadata.public_ipv6',metadata_public_ipv6,))
        if metadata_os_details:
            get_parameters.append(('metadata.os_details',metadata_os_details,))
        if metadata_os_type:
            get_parameters.append(('metadata.os_type',metadata_os_type,))
        if name:
            get_parameters.append(('name',name,))
        if search:
            get_parameters.append(('search',search,))
        if status_details:
            get_parameters.append(('status.details',status_details,))
        if status_status:
            get_parameters.append(('status.status',status_status,))
        if tags:
            get_parameters.append(('tags',tags,))
        if len(get_parameters):
            response = self._AlertLogic_get(path, get_parameters)
        else:
            response = self._AlertLogic_get(path)
        json = response.json()
        appliances = []
        if appliance_id:
            for appliance_id in appliance_id:
                appliances += [AlertLogicAppliance(j) for j in json if j['appliance_id'] == appliance_id]
        else:
            appliances += [AlertLogicAppliance(j) for j in json]
        return appliances
    #
    # def delete_appliance(self, appliance):
    #     path = 'latest/appliance/%s' % appliance.appliance_id
    #     response = self._AlertLogic_delete(path)
    #     return response
    #
    #
    # def list_hosts(self):
    #     hosts = self.get_all_hosts()
    #     host_list = [i.host_id for i in hosts]
    #     return host_list
    #
    #
    # def get_all_hosts(self, host_ids=None):
    #     path = 'latest/host'
    #     response = self._AlertLogic_get(path)
    #     json = response.json()
    #     hosts = []
    #     if host_ids:
    #         for host_id in host_ids:
    #             hosts += [AlertLogicHost(j) for j in json if j['host_id'] == host_id]
    #     else:
    #         hosts += [AlertLogicHost(j) for j in json]
    #     return hosts
    #
    #
    # def get_host(self, host_id):
    #     path = 'latest/host/%s' % host_id
    #     response = self._AlertLogic_get(path)
    #     host = AlertLogicHost(response.json())
    #     return host
    #
    #
    # def delete_host(self, host):
    #     path = 'latest/host/%s' % host.host_id
    #     response = self._AlertLogic_delete(path)
    #     return response
    #
    #
    # def add_host_to_appliance(self, host, appliance):
    #     path = 'latest/appliance/assign'
    #     put_data = {'appliance_id': appliance.appliance_id, 'host_id': host.host_id}
    #     response = self._AlertLogic_put(path, put_data)
    #     return response
    #
    #
    # def add_hosts_to_appliance(self, hosts, appliance):
    #     path = 'latest/appliance/assign'
    #     put_data = [('appliance_id',appliance.appliance_id,)]
    #     for host in hosts:
    #         put_data.append(('host_id',host.host_id,))
    #     response = self._AlertLogic_put(path, put_data)
    #     return response
    #
    #
    # def add_tag_to_host(self, host, tag_name, tag_value):
    #     path = 'latest/host/tag/%s' % host.host_id
    #     put_data = {'name': tag_name, 'value': tag_value}
    #     response = self._AlertLogic_put(path, put_data)
    #     return response
    #
    # def delete_tag_from_host(self, host, tag_name):
    #     path = 'latest/host/tag/%s' % host.host_id
    #     put_data = {'name': tag_name}
    #     response = self._AlertLogic_delete(path, put_data)
    #     return response
    #
    # def claim_appliance(self, instance_id, zone):
    #     path = 'latest/appliance/claim'
    #     payload = {'instance_id':instance_id,'zone':zone}
    #     response = self._AlertLogic_put_params(path,payload)
    #     return response