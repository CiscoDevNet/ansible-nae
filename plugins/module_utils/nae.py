# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component

# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.


# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from requests_toolbelt.multipart.encoder import MultipartEncoder
from datetime import datetime
import base64
import requests
import json
import os
import time
import gzip
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_bytes, to_native
from jsonpath_ng import jsonpath, parse


def nae_argument_spec():
    return dict(
        host=dict(type='str', required=True, aliases=['hostname']),
        port=dict(type='int', required=False, default=443),
        username=dict(type='str', default='admin', aliases=['user']),
        password=dict(type='str', no_log=True),
    )


class NAEModule(object):
    def __init__(self, module):
        self.module = module
        self.resp = {}
        self.params = module.params
        self.result = dict(changed=False)
        self.files = {}
        self.assuranceGroups = []
        self.session_cookie = ""
        self.error = dict(code=None, text=None)
        self.version = ""
        self.http_headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8,it;q=0.7',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Host': self.params.get('host'),
            'Content-Type': 'application/json;charset=utf-8',
            'Connection': 'keep-alive'}
        self.login()

    def login(self):
        url = 'https://%(host)s:%(port)s/nae/api/v1/whoami' % self.params
        resp, auth = fetch_url(self.module, url,
                               data=None,
                               method='GET')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=self.response, **self.result)
            except KeyError:
                # Connection error
                self.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)

        url = 'https://%(host)s:%(port)s/nae/api/v1/login' % self.params
        user_credentials = json.dumps({"username": self.params.get(
            'username'), "password": self.params.get('password'), "domain": 'Local'})
        self.http_headers['Cookie'] = resp.headers.get('Set-Cookie')
        self.session_cookie = resp.headers.get('Set-Cookie')
        self.http_headers['X-NAE-LOGIN-OTP'] = resp.headers.get(
            'X-NAE-LOGIN-OTP')
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=user_credentials,
                               method='POST')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        self.http_headers['X-NAE-CSRF-TOKEN'] = resp.headers['X-NAE-CSRF-TOKEN']

        # # Update with the authenticated Cookie
        self.http_headers['Cookie'] = resp.headers.get('Set-Cookie')

        # Remove the LOGIN-OTP from header, it is only needed at the beginning
        self.http_headers.pop('X-NAE-LOGIN-OTP', None)
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/candid-version' % self.params
        resp, auth = fetch_url(
            self.module, url, headers=self.http_headers, data=None, method='GET')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=self.response, **self.result)
            except KeyError:
                # Connection error
                self.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        self.version = json.loads(
            resp.read())['value']['data']['candid_version']
        # self.result['response'] = data

    def get_all_assurance_groups(self):
        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assured-networks/aci-fabric/' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        if resp.headers['Content-Encoding'] == "gzip":
            r = gzip.decompress(resp.read())
            self.assuranceGroups = json.loads(r.decode())['value']['data']
            return
        self.assuranceGroups = json.loads(resp.read())['value']['data']

    def get_assurance_group(self, name):
        self.get_all_assurance_groups()
        for ag in self.assuranceGroups:
            if ag['unique_name'] == name:
                return ag
        return None

    def deleteAG(self):
        self.params['uuid'] = str(
            self.get_assurance_group(
                self.params.get('name'))['uuid'])
        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assured-networks/aci-fabric/%(uuid)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='DELETE')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=self.response, **self.result)
            except KeyError:
                # Connection error
                self.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        if json.loads(resp.read())['success'] is True:
            self.result['Result'] = 'Assurance Group "%(name)s" deleted successfully' % self.params

    def newOnlineAG(self):
        # This method creates a new Offline Assurance Group, you only need to
        # pass the AG Name.

        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assured-networks/aci-fabric/' % self.params

        form = '''{
          "analysis_id": "",
          "display_name": "",
          "description": "",
          "interval": 900,
          "password": "''' + str(self.params.get('apic_password')) + '''",
          "operational_mode": "ONLINE",
          "status": "STOPPED",
          "active": true,
          "unique_name": "''' + str(self.params.get('name')) + '''",
          "assured_network_type": "",
          "apic_hostnames": [ "''' + str(self.params.get('apic_hostnames')) + '''" ],
          "username": "''' + str(self.params.get('apic_username')) + '''",
          "analysis_timeout_in_secs": 3600,
          "apic_configuration_export_policy": {
            "apic_configuration_export_policy_enabled": "''' + str(self.params.get('export_apic_policy')) + '''",
            "export_format": "JSON",
            "export_policy_name": "''' + str(self.params.get('name')) + '''"
          },
          "nat_configuration": null,
          "assured_fabric_type": null,
          "analysis_schedule_id": ""}'''

        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=form,
                               method='POST')

        if auth.get('status') != 201:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(
                    msg=str(self.response) + str(self.status), **self.result)
            except KeyError:
                # Connection error
                self.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        self.result['Result'] = 'Successfully created Assurance Group "%(name)s"' % self.params

    def newOfflineAG(self):
        # This method creates a new Offline Assurance Group, you only need to
        # pass the AG Name.

        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assured-networks/aci-fabric/' % self.params

        form = '''{
          "analysis_id": "",
          "display_name": "",
          "description": "",
          "operational_mode": "OFFLINE",
          "status": "STOPPED",
          "active": true,
          "unique_name": "''' + str(self.params.get('name')) + '''",
          "assured_network_type": "",
          "analysis_timeout_in_secs": 3600,
          "apic_configuration_export_policy": {
            "apic_configuration_export_policy_enabled": false,
            "export_format": "XML",
            "export_policy_name": ""
          },
          "analysis_schedule_id": ""}'''

        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=form,
                               method='POST')

        if auth.get('status') != 201:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(
                    msg=str(self.response) + str(self.status), **self.result)
            except KeyError:
                # Connection error
                self.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        self.result['Result'] = 'Successfully created Assurance Group "%(name)s"' % self.params

    def get_pre_change_analyses(self):
        self.params['fabric_id'] = str(
            self.get_assurance_group(
                self.params.get('ag_name'))['uuid'])
        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis?fabric_id=%(fabric_id)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')
        # self.result['resp'] = resp.headers.get('Set-Cookie')
        # self.module.fail_json(msg="err", **self.result)
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        if resp.headers['Content-Encoding'] == "gzip":
            r = gzip.decompress(resp.read())
            return json.loads(r.decode())['value']['data']
        return json.loads(resp.read())['value']['data']

    def show_pre_change_analyses(self):
        result = self.get_pre_change_analyses()
        for x in result:
            if 'description' not in x:
                x['description'] = ""
            if 'job_id' in x:
                del x['job_id']
            if 'fabric_uuid' in x:
                del x['fabric_uuid']
            if 'base_epoch_id' in x:
                del x['base_epoch_id']
            if 'base_epoch_collection_time_rfc3339':
                del x['base_epoch_collection_time_rfc3339']
            if 'pre_change_epoch_uuid' in x:
                del x['pre_change_epoch_uuid']
            if 'analysis_schedule_id' in x:
                del x['analysis_schedule_id']
            if 'epoch_delta_job_id' in x:
                del x['epoch_delta_job_id']
            if 'enable_download' in x:
                del x['enable_download']
            if 'allow_unsupported_object_modification' in x:
                del x['allow_unsupported_object_modification']
            if 'changes' in x:
                del x['changes']
            if 'change_type' in x:
                del x['change_type']
            if 'uploaded_file_name' in x:
                del x['uploaded_file_name']
            if 'stop_analysis' in x:
                del x['stop_analysis']
            if 'submitter_domain' in x:
                del x['submitter_domain']

            m = str(x['base_epoch_collection_timestamp'])[:10]
            dt_object = datetime.fromtimestamp(int(m))
            x['base_epoch_collection_timestamp'] = dt_object

            m = str(x['analysis_submission_time'])[:10]
            dt_object = datetime.fromtimestamp(int(m))
            x['analysis_submission_time'] = dt_object
        self.result['Analyses'] = result
        return result

    def is_json(self, myjson):
        try:
            json_object = json.loads(myjson)
        except ValueError as e:
            return False
        return True

    def get_pre_change_analysis(self):
        ret = self.get_pre_change_analyses()
        # self.result['ret'] = ret
        for a in ret:
            if a['name'] == self.params.get('name'):
                # self.result['analysis'] = a
                return a
        return None

    def get_pre_change_result(self):
        if self.get_assurance_group(self.params.get('ag_name')) is None:
            self.module.exit_json(
                msg='No such Assurance Group exists on this fabric.')
        self.params['fabric_id'] = str(
            self.get_assurance_group(
                self.params.get('ag_name'))['uuid'])
        if self.get_pre_change_analysis() is None:
            self.module.fail_json(
                msg='No such Pre-Change Job exists.',
                **self.result)
        if self.params['verify']:
            status = None
            while status != "COMPLETED":
                try:
                    status = str(
                        self.get_pre_change_analysis()['analysis_status'])
                    if status == "COMPLETED":
                        break
                except BaseException:
                    pass
                time.sleep(30)
        else:
            job_is_done = str(
                self.get_pre_change_analysis()['analysis_status'])
            if job_is_done != "COMPLETED":
                self.module.exit_json(
                    msg='Pre-Change Job has not yet completed.', **self.result)
        self.params['epoch_delta_job_id'] = str(
            self.get_pre_change_analysis()['epoch_delta_job_id'])
        url = 'https://%(host)s:%(port)s/nae/api/v1/epoch-delta-services/assured-networks/%(fabric_id)s/job/%(epoch_delta_job_id)s/health/view/aggregate-table?category=ADC,CHANGE_ANALYSIS,TENANT_ENDPOINT,TENANT_FORWARDING,TENANT_SECURITY,RESOURCE_UTILIZATION,SYSTEM,COMPLIANCE&epoch_status=EPOCH2_ONLY&severity=EVENT_SEVERITY_CRITICAL,EVENT_SEVERITY_MAJOR,EVENT_SEVERITY_MINOR,EVENT_SEVERITY_WARNING,EVENT_SEVERITY_INFO' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')
        if auth.get('status') != 200:
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)
        if resp.headers['Content-Encoding'] == "gzip":
            r = gzip.decompress(resp.read())
            result = json.loads(r.decode())['value']['data']
        else:
            result = json.loads(resp.read())['value']['data']
        count = 0
        for x in result:
            if int(x['count']) > 0:
                if str(x['epoch2_details']['severity']) == "EVENT_SEVERITY_INFO":
                     continue
                    # with open("output.txt", 
                count = count + 1 
        if(count != 0):
            self.result['Later Epoch Smart Events'] = result
            self.module.fail_json(
                msg="Pre-change analysis failed. The above smart events have been detected for later epoch only.",
                **self.result)
            return False
        return "Pre-change analysis '%(name)s' passed." % self.params

    def create_pre_change_from_manual_changes(self):
        self.params['file'] = None
        self.send_manual_payload()

    def send_manual_payload(self):
        self.params['fabric_id'] = str(
            self.get_assurance_group(
                self.params.get('ag_name'))['uuid'])
        self.params['base_epoch_id'] = str(self.get_epochs()[0]["epoch_id"])
        if '4.1' in self.version:
            f = self.params['file']
            fields = {
                ('data',
                 (f,

                  # content to upload
                  '''{
                                    "name": "''' + self.params.get('name') + '''",
                                    "fabric_uuid": "''' + self.params.get('fabric_id') + '''",
                                    "base_epoch_id": "''' + self.params.get('base_epoch_id') + '''",

                                    "changes": ''' + self.params.get('changes') + ''',
                                    "stop_analysis": false,
                                    "change_type": "CHANGE_LIST"
                                    }'''                            # The content type of the file
                  , 'application/json'))
            }
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis' % self.params
            m = MultipartEncoder(fields=fields)
            h = self.http_headers.copy()
            h['Content-Type'] = m.content_type
            resp, auth = fetch_url(self.module, url,
                                   headers=h,
                                   data=m,
                                   method='POST')

            if auth.get('status') != 200:
                if('filename' in self.params):
                    self.params['file'] = self.params['filename']
                    del self.params['filename']
                self.result['status'] = auth['status']
                self.module.exit_json(msg=json.loads(
                    auth.get('body'))['messages'][0]['message'], **self.result)

            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']

            self.result['Result'] = "Pre-change analysis %(name)s successfully created." % self.params

        elif '5.0' in self.version:
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/manual-changes?action=RUN' % self.params
            form = '''{
                                    "name": "''' + self.params.get('name') + '''",
                                    "allow_unsupported_object_modification": true,
                                    "uploaded_file_name": null,
                                    "stop_analysis": false,
                                    "fabric_uuid": "''' + self.params.get('fabric_id') + '''",
                                    "base_epoch_id": "''' + self.params.get('base_epoch_id') + '''",
                                    "imdata": ''' + self.params.get('changes') + '''
                                    }'''

            resp, auth = fetch_url(self.module, url,
                                   headers=self.http_headers,
                                   data=form,
                                   method='POST')

            if auth.get('status') != 200:
                if('filename' in self.params):
                    self.params['file'] = self.params['filename']
                    del self.params['filename']
                self.result['status'] = auth['status']
                self.module.exit_json(msg=json.loads(
                    auth.get('body'))['messages'][0]['message'], **self.result)

            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']

            self.result['Result'] = "Pre-change analysis %(name)s successfully created." % self.params

    def create_pre_change_from_file(self):
        no_parse = False
        if not os.path.exists(self.params.get('file')):
            raise AssertionError("File not found, " +
                                 str(self.params.get('file')))
        filename = self.params.get('file')
        self.params['filename'] = filename
        # self.result['Checking'] = str(self.params.get('filename'))
        # self.module.exit_json(msg="Testing", **self.result)
        f = open(self.params.get('file'), "rb")
        if self.is_json(f.read()) is True:
            no_parse = True
        if self.params['verify'] and no_parse is False:
            # # Input file is not parsed.
            self.params['cmap'] = {}
            data = self.load(open(self.params.get('file')))
            tree = self.construct_tree(data)
            if tree is False:
                self.module.fail_json(
                    msg="Error parsing input file, unsupported object found in heirarchy.",
                    **self.result)
            tree_roots = self.find_tree_roots(tree)
            ansible_ds = {}
            for root in tree_roots:
                exp = self.export_tree(root)
                for key, val in exp.items():
                    ansible_ds[key] = val
            self.copy_children(ansible_ds)
            toplevel = {"totalCount": "1", "imdata": []}
            toplevel['imdata'].append(ansible_ds)
            with open(self.params.get('file'), 'w') as f:
                json.dump(toplevel, f)
            del self.params['cmap']
            f.close()

        # self.result['Checking'] = f
        # self.module.exit_json(msg="Testing", **self.result)
        config = []
        self.params['file'] = f
        self.params['changes'] = config
        self.send_pre_change_payload()

    def copy_children(self, tree):
        '''
        Copies existing children objects to the built tree

        '''
        cmap = self.params['cmap']
        for dn, children in cmap.items():
            aci_class = self.get_aci_class(
                (self.parse_path(dn)[-1]).split("-")[0])
            json_path_expr_search = parse(f'$..children.[*].{aci_class}')
            json_path_expr_update = parse(str([str(match.full_path) for match in json_path_expr_search.find(
                tree) if match.value['attributes']['dn'] == dn][0]))
            curr_obj = [
                match.value for match in json_path_expr_update.find(tree)][0]
            if 'children' in curr_obj:
                for child in children:
                    curr_obj['children'].append(child)
            elif 'children' not in curr_obj:
                curr_obj['children'] = []
                for child in children:
                    curr_obj['children'].append(child)
            json_path_expr_update.update(curr_obj, tree)

        return

    def load(self, fh, chunk_size=1024):
        depth = 0
        in_str = False
        items = []
        buffer = ""

        while True:
            chunk = fh.read(chunk_size)
            if len(chunk) == 0:
                break
            i = 0
            while i < len(chunk):
                c = chunk[i]
                # if i == 0 and c != '[':
                # self.module.fail_json(msg="Input file invalid or already parsed.", **self.result)
                buffer += c

                if c == '"':
                    in_str = not in_str
                elif c == '[':
                    if not in_str:
                        depth += 1
                elif c == ']':
                    if not in_str:
                        depth -= 1
                elif c == '\\':
                    buffer += f[i + 1]
                    i += 1

                if depth == 0:
                    if len(buffer.strip()) > 0:
                        j = json.loads(buffer)
                        assert isinstance(j, list)
                        items += j
                    buffer = ""

                i += 1

        assert depth == 0
        return items

    def parse_path(self, dn):
        """
        Grouping aware extraction of items in a path
        E.g. for /a[b/c/d]/b/c/d/e extracts [a[b/c/d/], b, c, d, e]
        """

        path = []
        buffer = ""
        i = 0
        while i < len(dn):
            if dn[i] == '[':
                while i < len(dn) and dn[i] != ']':
                    buffer += dn[i]
                    i += 1

            if dn[i] == '/':
                path.append(buffer)
                buffer = ""
            else:
                buffer += dn[i]

            i += 1

        path.append(buffer)
        return path

    def construct_tree(self, item_list):
        """
        Given a flat list of items, each with a dn. Construct a tree represeting their relative relationships.
        E.g. Given [/a/b/c/d, /a/b, /a/b/c/e, /a/f, /z], the function will construct

        __root__
          - a (no data)
             - b (data of /a/b)
               - c (no data)
                 - d (data of /a/b/c/d)
                 - e (data of /a/b/c/e)
             - f (data of /a/f)
          - z (data of /z)

        __root__ is a predefined name, you could replace this with a flag root:True/False
        """
        tree = {'data': None, 'name': '__root__', 'children': {}}

        for item in item_list:
            for nm, desc in item.items():
                assert 'attributes' in desc
                attr = desc['attributes']
                assert 'dn' in attr
                if 'children' in desc:
                    existing_children = desc['children']
                    self.params['cmap'][attr['dn']] = existing_children
                path = self.parse_path(attr['dn'])
                cursor = tree
                prev_node = None
                curr_node_dn = ""
                for node in path:
                    curr_node_dn += "/" + str(node)
                    if curr_node_dn[0] == "/":
                        curr_node_dn = curr_node_dn[1:]
                    if node not in cursor['children']:
                        if node == 'uni':
                            cursor['children'][node] = {
                                'data': None,
                                'name': node,
                                'children': {}
                            }
                        else:
                            aci_class_identifier = node.split("-")[0]
                            aci_class = self.get_aci_class(
                                aci_class_identifier)
                            if not aci_class:
                                return False
                            data_dic = {}
                            data_dic['attributes'] = dict(dn=curr_node_dn)
                            cursor['children'][node] = {
                                'data': (aci_class, data_dic),
                                'name': node,
                                'children': {}
                            }
                    cursor = cursor['children'][node]
                    prev_node = node
                cursor['data'] = (nm, desc)
                cursor['name'] = path[-1]

        return tree

    def get_aci_class(self, prefix):
        """
        Contains a hardcoded mapping between dn prefix and aci class.

        E.g for the input identifier prefix of "tn"
        this function will return "fvTenant"

        """

        if prefix == "tn":
            return "fvTenant"
        elif prefix == "epg":
            return "fvAEPg"
        elif prefix == "rscons":
            return "fvRsCons"
        elif prefix == "rsprov":
            return "fvRsProv"
        elif prefix == "rsdomAtt":
            return "fvRsDomAtt"
        elif prefix == "attenp":
            return "infraAttEntityP"
        elif prefix == "rsdomP":
            return "infraRsDomP"
        elif prefix == "ap":
            return "fvAp"
        elif prefix == "BD":
            return "fvBD"
        elif prefix == "subnet":
            return "fvSubnet"
        elif prefix == "rsBDToOut":
            return "fvRsBDToOut"
        elif prefix == "brc":
            return "vzBrCP"
        elif prefix == "subj":
            return "vzSubj"
        elif prefix == "rssubjFiltAtt":
            return "vzRsSubjFiltAtt"
        elif prefix == "flt":
            return "vzFilter"
        elif prefix == "e":
            return "vzEntry"
        elif prefix == "out":
            return "l3extOut"
        elif prefix == "instP":
            return "l3extInstP"
        elif prefix == "extsubnet":
            return "l3extSubnet"
        elif prefix == "rttag":
            return "l3extRouteTagPol"
        elif prefix == "rspathAtt":
            return "fvRsPathAtt"
        elif prefix == "leaves":
            return "infraLeafS"
        elif prefix == "taboo":
            return "vzTaboo"
        elif prefix == "destgrp":
            return "spanDestGrp"
        elif prefix == "srcgrp":
            return "spanSrcGrp"
        elif prefix == "spanlbl":
            return "spanSpanLbl"
        elif prefix == "ctx":
            return "fvCtx"
        else:
            return False

    def find_tree_roots(self, tree):
        """
        Find roots for tree export. This involves finding all "fake" (dataless) nodes.

        E.g. for the tree
        __root__
          - a (no data)
             - b (data of /a/b)
               - c (no data)
                 - d (data of /a/b/c/d)
                 - e (data of /a/b/c/e)
             - f (data of /a/f)
          - z (data of /z)

        This function will return [__root__, a, c]
        """
        if tree['data'] is not None:
            return [tree]

        roots = []
        for child in tree['children'].values():
            roots += self.find_tree_roots(child)

        return roots

    def export_tree(self, tree):
        """
        Exports the constructed tree to a heirachial json representation. (equal to tn-ansible, except for ordering)
        """
        tree_data = {
            'attributes': tree['data'][1]['attributes']
        }
        children = []
        for child in tree['children'].values():
            children.append(self.export_tree(child))

        if len(children) > 0:
            tree_data['children'] = children

        return {tree['data'][0]: tree_data}

    def delete_pre_change_analysis(self):
        if self.get_pre_change_analysis() is None:
            self.module.exit_json(msg='No such Pre-Change Job exists.')
        self.params['job_id'] = str(self.get_pre_change_analysis()['job_id'])

        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/%(job_id)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='DELETE')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        self.result['msg'] = json.loads(resp.read())['value']['data']

    def get_epochs(self):
        self.params['fabric_id'] = str(
            self.get_assurance_group(
                self.params.get('ag_name'))['uuid'])
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/assured-networks/%(fabric_id)s/epochs?$sort=-collectionTimestamp' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        if resp.headers['Content-Encoding'] == "gzip":
            r = gzip.decompress(resp.read())
            return json.loads(r.decode())['value']['data']
        return json.loads(resp.read())['value']['data']

    def send_pre_change_payload(self):
        self.params['fabric_id'] = str(
            self.get_assurance_group(
                self.params.get('ag_name'))['uuid'])
        self.params['base_epoch_id'] = str(self.get_epochs()[0]["epoch_id"])
        f = self.params.get('file')
        payload = {
            "name": self.params.get('name'),
            "fabric_uuid": self.params.get('fabric_id'),
            "base_epoch_id": self.params.get('base_epoch_id'),
            "stop_analysis": False
        }

        if '4.1' in self.version:
            payload['change_type'] = "CONFIG_FILE"
            payload['changes'] = self.params.get('changes')
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis' % self.params

        elif '5.0' in self.version:
            payload['allow_unsupported_object_modification'] = 'true'
            payload['uploaded_file_name'] = str(self.params.get('filename'))
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/file-changes' % self.params


        files = {"file": (str(self.params.get('filename')),
                          open(str(self.params.get('filename')),
                               'rb'),
                          'application/json'),
                 "data": ("blob",
                          json.dumps(payload),
                          'application/json')}
       
        m = MultipartEncoder(fields=files)
        
        #Need to set the right content type for the multi part upload! 
        h = self.http_headers.copy()
        h['Content-Type'] = m.content_type

        resp, auth = fetch_url(self.module, url,
                               headers=h,
                               data=m,
                               method='POST')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params['filename']
                del self.params['filename']
            self.result['status'] = auth['status']
            self.module.exit_json(msg=json.loads(
                auth.get('body'))['messages'][0]['message'], **self.result)

        if('filename' in self.params):
            self.params['file'] = self.params['filename']
            del self.params['filename']

        self.result['Result'] = "Pre-change analysis %(name)s successfully created." % self.params

    

    def newObjectSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Object Selectors created")
        else:
           self.logger.info("Object Selectors creation failed with error message \n %s",req.json())

    def newTrafficSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/traffic-selectors'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Traffic Selectors created")
        else:
           self.logger.info("Traffic Selectors creation failed with error message \n %s",req.json())

    def newComplianceRequirement(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirements'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Compliance Requirement created")
        else:
           self.logger.info("Compliance Requirement creation failed with error message \n %s",req.json())

    def newComplianceRequirementSet(self, form):
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirement-sets'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Complianc Requirement Set created")
        else:
           self.logger.info("Complianc Requirement Set creation failed with error message \n %s",req.json())


    def getFirstAG(self):
        # Some API requires an Assurance grup in the API call even if does not matter which AG you select
        # For this I have created this methodggGG
        self.get_all_assurance_groups()
        return self.assuranceGroups[0]     





