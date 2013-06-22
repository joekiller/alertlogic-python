# Author: Joseph Lawson <joe@joekiller.com>
# Copyright 2013 Joseph Lawson.
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
from alertlogic.policy import AlertLogicPolicy
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

    def _AlertLogic_get(self, path):
        url = '%s/%s' % (self.base_url, path)
        headers=self.accept_header
        headers['Content-Length'] = '0'
        return requests.get(url,
                            auth=self._add_auth(),
                            headers=self.accept_header)

    def _AlertLogic_get_params(self, path, params):
        url = '%s/%s' % (self.base_url, path)
        headers=self.accept_header
        headers['Content-Length'] = '0'
        return requests.get(url,
                            auth=self._add_auth(),
                            headers=self.accept_header,
                            params=params)

    def _AlertLogic_put(self, path, put_data):
        url = '%s/%s' % (self.base_url, path)
        # Using tuples instead of dictionary for data so we must encode into a string
        data = urllib.urlencode(put_data)
        headers = self.accept_header
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return requests.put(url,
                            auth=self._add_auth(),
                            headers=headers,
                            data=data)

    def _AlertLogic_post(self, path, post_data):
        url = '%s/%s' % (self.base_url, path)
        # Using tuples instead of dictionary for data so we must encode into a string
        data = urllib.urlencode(post_data)
        headers = self.accept_header
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return requests.post(url,
                             auth=self._add_auth(),
                             headers=headers,
                             data=data)

    def _AlertLogic_put_params(self, path, params):
        url = '%s/%s' % (self.base_url, path)
        headers = self.accept_header
        headers['Content-Length'] = '0'
        return requests.put(url,
                            auth=self._add_auth(),
                            headers=headers,
                            params=params)

    def _AlertLogic_post_params(self, path, post_data, params):
        url = '%s/%s' % (self.base_url, path)
        data = urllib.urlencode(post_data)
        headers = self.accept_header
        headers['Content-Length'] = '0'
        return requests.put(url,
                            auth=self._add_auth(),
                            headers=headers,
                            params=params,
                            data=data)

    def _AlertLogic_delete(self, path, put_data=None):
        url = '%s/%s' % (self.base_url, path)
        if put_data:
            data = urllib.urlencode(put_data)
            return requests.delete(url,
                                   auth=self._add_auth(),
                                   headers=self.accept_header,
                                   data=data)
        else:
            headers = self.accept_header
            headers['Content-Length'] = '0'
            return requests.delete(url,
                                   auth=self._add_auth(),
                                   headers=headers)

    def get_all_appliances(self,
                           config_time_zone=None,
                           appliance_id=None,
                           metadata_local_hostname=None,
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
            get_parameters['config.time_zone'] = config_time_zone
        if appliance_id:
            get_parameters['id'] = appliance_id
        if metadata_local_hostname:
            get_parameters['metadata.local_hostname'] = metadata_local_hostname
        if metadata_local_ipv4:
            get_parameters['metadata.local_ipv4'] = metadata_local_ipv4
        if metadata_local_ipv6:
            get_parameters['metadata.local_ipv6'] = metadata_local_ipv6
        if metadata_public_ipv4:
            get_parameters['metadata.public_ipv4'] = metadata_public_ipv4
        if metadata_public_ipv6:
            get_parameters['metadata.public_ipv6'] = metadata_public_ipv6
        if metadata_os_details:
            get_parameters['metadata.os_details'] = metadata_os_details
        if metadata_os_type:
            get_parameters['metadata.os_type'] = metadata_os_type
        if name:
            get_parameters['name'] = name
        if search:
            get_parameters['search'] = search
        if status_details:
            get_parameters['status.details'] = status_details
        if status_status:
            get_parameters['status.status'] = status_status
        if tags:
            get_parameters['tags'] = tags
        if len(get_parameters):
            response = self._AlertLogic_get_params(path, get_parameters)
        else:
            response = self._AlertLogic_get(path)
        json = response.json()
        return [AlertLogicAppliance(j) for j in json]

    def get_appliance(self, appliance_id):
        return self.retrieve_appliance(appliance_id=appliance_id)

    def retrieve_appliance(self, appliance_id):
        path = 'appliances/%s' % appliance_id
        response = self._AlertLogic_get(path)
        return AlertLogicAppliance(response.json())

    def edit_appliance(self, appliance_id, appliance_name=None, tags=None):
        path = 'appliances/%s' % appliance_id
        post_data = {'appliance': {'name': appliance_name}}
        if tags:
            post_data['appliance']['tags'] = [{'name': tag} for tag in tags]
        return self._AlertLogic_post(path, post_data)

    def replace_appliance(self, appliance_id, appliance_name, tags=None):
        path = 'appliances/%s' % appliance_id
        put_data = {'appliance': {'name': appliance_name}}
        if tags:
            put_data['appliance']['tags'] = [{'name': tag} for tag in tags]
        return self._AlertLogic_put(path, put_data)

    def list_policies(self,
                      appliance_assignment_appliances=None,
                      default=None,
                      policy_id=None,
                      name=None,
                      search=None,
                      tags=None,
                      tmhost_compress=None,
                      tmhost_encrypt=None,
                      tmhost_packet_size=None,
                      tmhost_udp=None,
                      policy_type=None):
        path = 'policies'
        get_parameters = dict()
        if appliance_assignment_appliances:
            get_parameters['appliance_assignment.appliances'] = appliance_assignment_appliances
        if default is not None:
            get_parameters['default'] = default
        if policy_id:
            get_parameters['id'] = policy_id
        if name:
            get_parameters['name'] = name
        if search:
            get_parameters['search'] = search
        if tags:
            get_parameters['tags'] = tags
        if tmhost_compress:
            get_parameters['tmhost.compress'] = tmhost_compress
        if tmhost_encrypt is not None:
            get_parameters['tmhost.encrypt'] = tmhost_encrypt
        if tmhost_packet_size:
            get_parameters['tmhost.packet_size'] = tmhost_packet_size
        if tmhost_udp is not None:
            get_parameters['tmhost.udp'] = tmhost_udp
        if policy_type:
            get_parameters['type'] = policy_type
        if len(get_parameters):
            response = self._AlertLogic_get_params(path, get_parameters)
        else:
            response = self._AlertLogic_get(path)
        json = response.json()
        policies = list(AlertLogicPolicy(j) for j in json)
        return policies

    def retrieve_policy(self, policy_id):
        path = 'policies/%s' % policy_id
        response = self._AlertLogic_get(path)
        return AlertLogicPolicy(response.json())

    def create_policy(self,
                      name,
                      policy_type,
                      appliance_assignment_ids=None,
                      encrypt=None,
                      tags=None):
        path = 'policies'
        post_data = {'policy': {'name': name}}
        if policy_type not in AlertLogicPolicy.POLICY_TYPES:
            raise Exception("policy_type %s must be one of the following values: %s"
                            % (policy_type, AlertLogicPolicy.POLICY_TYPES))
        post_data['policy']['type'] = policy_type
        if appliance_assignment_ids:
            if policy_type is 'appliance_assignment':
                post_data['policy']['appliance_assignment'] = {'appliances': appliance_assignment_ids}
            else:
                raise Exception("appliance_assignment parameter can only be used with appliance_assignment polices. "
                                "policy_type: %s" % policy_type)
        if encrypt is not None:
            if policy_type is 'tmhost':
                if encrypt is True:
                    post_data['policy']['tmhost'] = {'encrypt': 'true'}
                elif encrypt is False:
                    post_data['policy']['tmhost'] = {'encrypt': 'false'}
                else:
                    raise Exception("tmhost encrypt policy must be True or False.  encrypt: %s" % encrypt)
            else:
                raise Exception("tmhost encrypt parameter can only be used with tmhost policies. "
                                "policy_type %s" % policy_type)
        if tags:
            post_data['policy']['tags'] = [{'name': tag} for tag in tags]
        return self._AlertLogic_post(path, post_data)

    def edit_policy(self,
                    policy_id,
                    policy_name=None,
                    policy_type=None,
                    appliance_assignment_ids=None,
                    encrypt=None,
                    tags=None):
        path = 'policies/%s' % policy_id
        post_data = dict()
        if policy_name:
            post_data['policy'] = {'name': policy_name}
        if policy_type:
            if policy_type not in AlertLogicPolicy.POLICY_TYPES:
                raise Exception("policy_type %s must be one of the following values: %s"
                                % (policy_type, AlertLogicPolicy.POLICY_TYPES))
            if 'policy' in post_data:
                post_data['policy']['type'] = policy_type
            else:
                post_data['policy'] = {'type': policy_type}
        if appliance_assignment_ids:
            if policy_type is 'appliance_assignment':
                post_data['policy']['appliance_assignment'] = {'appliances': appliance_assignment_ids}
            else:
                raise Exception("appliance_assignment parameter can only be used with appliance_assignment polices. "
                                "policy_type: %s" % policy_type)
        if encrypt is not None:
            if policy_type is 'tmhost':
                if encrypt is True:
                    post_data['policy']['tmhost'] = {'encrypt': 'true'}
                elif encrypt is False:
                    post_data['policy']['tmhost'] = {'encrypt': 'false'}
                else:
                    raise Exception("tmhost encrypt policy must be True or False.  encrypt: %s" % encrypt)
            else:
                raise Exception("tmhost encrypt parameter can only be used with tmhost policies. "
                                "policy_type %s" % policy_type)
        if tags:
            if 'policy' in post_data:
                post_data['policy']['tags'] = [{'name': tag} for tag in tags]
            else:
                post_data['policy']= {'tags': [{'name': tag} for tag in tags]}
        return self._AlertLogic_post(path, post_data)

    def replace_policy(self,
                       policy_id,
                       policy_name,
                       policy_type=None,
                       appliance_assignment_ids=None,
                       encrypt=None,
                       tags=None):
        path = 'policies/%s' % policy_id
        put_data = {'policy': {'name': policy_name}}
        if policy_type not in AlertLogicPolicy.POLICY_TYPES:
            raise Exception("policy_type %s must be one of the following values: %s"
                            % (policy_type, AlertLogicPolicy.POLICY_TYPES))
        put_data['policy']['type'] = policy_type
        if appliance_assignment_ids:
            if policy_type is 'appliance_assignment':
                put_data['policy']['appliance_assignment'] = {'appliances': appliance_assignment_ids}
            else:
                raise Exception("appliance_assignment parameter can only be used with appliance_assignment polices. "
                                "policy_type: %s" % policy_type)
        if encrypt is not None:
            if policy_type is 'tmhost':
                if encrypt is True:
                    put_data['policy']['tmhost'] = {'encrypt': 'true'}
                elif encrypt is False:
                    put_data['policy']['tmhost'] = {'encrypt': 'false'}
                else:
                    raise Exception("tmhost encrypt policy must be True or False.  encrypt: %s" % encrypt)
            else:
                raise Exception("tmhost encrypt parameter can only be used with tmhost policies. "
                                "policy_type %s" % policy_type)
        if tags:
            put_data['policy']['tags'] = [{'name': tag} for tag in tags]
        return self._AlertLogic_put(path, put_data)

    def delete_policy(self, policy_id):
        path = 'policies/%s' % policy_id
        return self._AlertLogic_delete(path)

    def list_protected_hosts(self,
                             appliance_assigned_to=None,
                             appliance_connected_to=None,
                             appliance_policy_id=None,
                             config_policy_id=None,
                             config_time_zone=None,
                             protected_host_id=None,
                             metadata_local_hostname=None,
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
        path = 'protectedhosts'
        get_parameters = dict()
        if appliance_assigned_to:
            get_parameters['appliance.assigned_to'] = appliance_assigned_to
        if appliance_connected_to:
            get_parameters['appliance.connected_to'] = appliance_connected_to
        if appliance_policy_id:
            get_parameters['appliance.policy.id'] = appliance_policy_id
        if config_policy_id:
            get_parameters['config.policy.id'] = config_policy_id
        if config_time_zone:
            get_parameters['config.time_zone'] = config_time_zone
        if protected_host_id:
            get_parameters['id'] = protected_host_id
        if metadata_local_hostname:
            get_parameters['metadata.local_hostname'] = metadata_local_hostname
        if metadata_local_ipv4:
            get_parameters['metadata.local_ipv4'] = metadata_local_ipv4
        if metadata_local_ipv6:
            get_parameters['metadata.local_ipv6'] = metadata_local_ipv6
        if metadata_public_ipv4:
            get_parameters['metadata.public_ipv4'] = metadata_public_ipv4
        if metadata_public_ipv6:
            get_parameters['metadata.public_ipv6'] = metadata_public_ipv6
        if metadata_os_details:
            get_parameters['metadata.os_details'] = metadata_os_details
        if metadata_os_type:
            get_parameters['metadata.os_type'] = metadata_os_type
        if name:
            get_parameters['name'] = name
        if search:
            get_parameters['search'] = search
        if status_details:
            get_parameters['status.details'] = status_details
        if status_status:
            get_parameters['status.status'] = status_status
        if tags:
            get_parameters['tags'] = tags
        if len(get_parameters):
            response = self._AlertLogic_get_params(path, get_parameters)
        else:
            response = self._AlertLogic_get(path)
        json = response.json()
        return [AlertLogicHost(j) for j in json]

    def retrieve_protected_host(self, protected_host_id):
        path = 'protectedhosts/%s' % protected_host_id
        response = self._AlertLogic_get(path)
        return AlertLogicHost(response.json())

    def edit_protected_host(self, protected_host_id, protected_host_name=None, tags=None):
        path = 'protectedhosts/%s' % protected_host_id
        post_data = {}
        if protected_host_name:
            post_data['protectedhost'] = {'name': protected_host_name}
        if tags:
            if 'protectedhost' in post_data:
                post_data['protectedhost']['tags'] = [{'name': tag} for tag in tags]
            else:
                post_data['protectedhost'] = {'tags': [{'name': tag} for tag in tags]}
        return self._AlertLogic_post(path, post_data)

    def replace_protected_host(self, protected_host_id, protected_host_name, tags=None):
        path = 'protectedhosts/%s' % protected_host_id
        post_data = {'protectedhost': {'name': protected_host_name}}
        if tags:
            post_data['protectedhost']['tags'] = [{'name': tag} for tag in tags]
        return self._AlertLogic_post(path, post_data)
