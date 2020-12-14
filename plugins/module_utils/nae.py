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
import csv
import json
import os
import sys
import time
import gzip
import filelock
import pathlib
import hashlib
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
        self.files = []
        self.assuranceGroups = []
        self.offlineAnalysis = []
        self.session_cookie = ""
        self.error = dict(code=None, text=None)
        self.version = ""
        self.http_headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8,it;q=0.7',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Host': self.params.get('host'),
            'Content-Type': 'application/json;charset=utf-8',
            'Connection': 'keep-alive'}
        self.login()

    def __del__(self):
        url = 'https://%(host)s:%(port)s/nae/api/v1/logout' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='POST')

    def login(self):
        url = 'https://%(host)s:%(port)s/nae/api/v1/whoami' % self.params
        resp, auth = fetch_url(self.module, url,
                               data=None,
                               method='GET')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=self.response, **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' % auth,
                    **self.result)

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
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            try:
                self.module.fail_json(
                    msg=json.loads(auth.get('body'))['messages'][0]['message'],
                    **self.result)
            except Exception:
                self.module.fail_json(
                    msg='Login failed for %(url)s. %(msg)s' % auth,
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
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.response = auth.get('msg')
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=self.response, **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        self.version = json.loads(
            resp.read())['value']['data']['candid_version']
        # self.result['response'] = data

    def get_logout_lock(self):
        # This lock has been introduced because logout and file upload cannot be
        # done in parallel. This is because logout incorrectly aborts all file
        # uploads by a user (not just that session). So, this lock must be
        # acquired for logout and file upload.
        lock_filename = "logout.lock"
        try:
            pathlib.Path(lock_filename).touch(exist_ok=False)
        except OSError:
            pass
        return filelock.FileLock(lock_filename)

    def get_all_assurance_groups(self):
        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assured-networks/aci-fabric/' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.module.fail_json(
                msg=json.loads(auth.get('body'))['messages'][0]['message'],
                **self.result)

        if resp.headers.get('Content-Encoding') == "gzip":
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
        ag = self.get_assurance_group(self.params.get('name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('name')), **self.result)
        else:
            self.params['uuid'] = str(ag.get('uuid'))
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assurance-group/fabric/%(uuid)s' % self.params
            resp, auth = fetch_url(self.module, url,
                                   headers=self.http_headers,
                                   data=None,
                                   method='DELETE')
            if auth.get('status') != 200:
                if('filename' in self.params):
                    self.params['file'] = self.params.get('filename')
                    del self.params['filename']
                self.response = auth.get('msg')
                self.status = auth.get('status')
                try:
                    self.module.fail_json(msg=self.response, **self.result)
                except KeyError:
                    # Connection error
                    self.module.fail_json(
                        msg='Connection failed for %(url)s. %(msg)s' %
                        auth, **self.result)
            if json.loads(resp.read())['success'] is True:
                self.result['Result'] = 'Assurance Group "%(name)s" deleted successfully' % self.params

    def newOnlineAG(self):
        # This method creates a new Offline Assurance Group, you only need to
        # pass the AG Name.

        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assurance-group/fabric' % self.params

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
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.response = json.loads(auth.get('body'))
            self.status = auth.get('status')
            try:
                self.module.fail_json(
                    msg=str(self.response['messages'][0]['message']), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' % auth,
                    **self.result)
        self.result['Result'] = 'Successfully created Assurance Group "%(name)s"' % self.params

    def newOfflineAG(self):
        self.get_all_assurance_groups()
        self.params['ag'] = [ag for ag in self.assuranceGroups if ag.get('unique_name') == self.params.get('name')]
        if self.params.get('ag') != []:
            self.module.exit_json(msg="WARNING: An assurance group with the same name already exist!!!", **self.result)
        # This method creates a new Offline Assurance Group, you only need to
        # pass the AG Name.

        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assurance-group/fabric' % self.params
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
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.response = json.loads(auth.get('body'))
            self.status = auth.get('status')
            try:
                self.module.fail_json(
                    msg=str(self.response['messages'][0]['message']), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' % auth,
                    **self.result)
        self.result['Result'] = 'Successfully created Assurance Group "%(name)s"' % self.params

    def get_pre_change_analyses(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis?fabric_id=%(fabric_id)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.module.fail_json(
                msg=json.loads(auth.get('body'))['messages'][0]['message'],
                **self.result)

        if resp.headers.get('Content-Encoding') == "gzip":
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
            if 'base_epoch_collection_time_rfc3339' in x:
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
        for a in ret:
            if a['name'] == self.params.get('name'):
                return a
        return None

    def get_pre_change_result(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(
                msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')),
                **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        if self.get_pre_change_analysis() is None:
            self.module.fail_json(
                msg='No such Pre-Change Job exists.',
                **self.result)
        if self.params.get('verify'):
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
        url = 'https://%(host)s:%(port)s/nae/api/v1/epoch-delta-services/' \
              'assured-networks/%(fabric_id)s/job/%(epoch_delta_job_id)s/' \
              'health/view/aggregate-table?category=ADC,CHANGE_ANALYSIS,' \
              'TENANT_ENDPOINT,TENANT_FORWARDING,TENANT_SECURITY,RESOURCE_UTILIZATION,' \
              'SYSTEM,COMPLIANCE&epoch_status=EPOCH2_ONLY&severity=EVENT_SEVERITY_CRITICAL,' \
              'EVENT_SEVERITY_MAJOR,EVENT_SEVERITY_MINOR,EVENT_SEVERITY_WARNING,EVENT_SEVERITY_INFO' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')
        if auth.get('status') != 200:
            self.module.exit_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)
        if resp.headers.get('Content-Encoding') == "gzip":
            r = gzip.decompress(resp.read())
            result = json.loads(r.decode())['value']['data']
        else:
            result = json.loads(resp.read())['value']['data']
        count = 0
        for x in result:
            suppressed_event_list = self.params.get('ignore_sm')
            if int(x['count']) > 0:
                if str(x['epoch2_details']['severity']) == "EVENT_SEVERITY_INFO" or str(x['epoch2_details']['mnemonic']) in suppressed_event_list:
                    continue
                count = count + 1
        if(count != 0):
            self.result['Later Epoch Smart Events'] = result
            self.module.fail_json(
                msg="Pre-change analysis failed. The above smart events have been detected for later epoch only.",
                **self.result)
            return False
        return "Pre-change analysis '%(name)s' passed." % self.params

    def get_delta_result(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        if self.get_delta_analysis() is None:
            self.module.fail_json(
                msg='No such Delta analysis exists.',
                **self.result)
        job_is_done = str(
            self.get_delta_analysis()['status'])
        if job_is_done != "COMPLETED_SUCCESSFULLY":
            self.module.exit_json(
                msg='Delta analysis has not yet completed.', **self.result)
        self.params['uuid'] = str(
            self.get_delta_analysis()['uuid'])
        url = 'https://%(host)s:%(port)s/nae/api/v1/epoch-delta-services' \
              '/assured-networks/%(fabric_id)s/job/%(uuid)s/health/view'\
              '/aggregate-table?category=ADC,CHANGE_ANALYSIS,TENANT_ENDPOINT,'\
              'TENANT_FORWARDING,TENANT_SECURITY,RESOURCE_UTILIZATION,SYSTEM,'\
              'COMPLIANCE&epoch_status=EPOCH2_ONLY&severity=EVENT_SEVERITY_CRITICAL,'\
              'EVENT_SEVERITY_MAJOR,EVENT_SEVERITY_MINOR,EVENT_SEVERITY_WARNING,'\
              'EVENT_SEVERITY_INFO' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')
        if auth.get('status') != 200:
            self.module.fail_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)
        if resp.headers.get('Content-Encoding') == "gzip":
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
                msg="Delta analysis failed. The above smart events have been detected for later epoch only.",
                **self.result)
            return False
        return "Delta analysis '%(name)s' passed." % self.params

    def create_pre_change_from_manual_changes(self):
        self.params['file'] = None
        self.send_manual_payload()

    def send_manual_payload(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        epochs = self.get_epochs()
        if not epochs:
            self.result['Result'] = "No Epochs found in Assurance group {0}".format(self.params.get('ag_name'))
            self.module.fail_json(msg='No Epochs found in Assurance group {0}'.format(self.params.get('ag_name')), **self.result)
        self.params['base_epoch_id'] = str(self.get_epochs()[0]["epoch_id"])
        if '4.1' in self.version:
            f = self.params.get('file')
            content_json = {
                "name": self.params.get('name'),
                "fabric_uuid": str(self.params.get('fabric_id')),
                "base_epoch_id": str(self.params.get('base_epoch_id')),
                "changes": self.params.get('changes'),
                "stop_analysis": False,
                "change_type": "CHANGE_LIST"
            }
            fields = {
                "data": (f, json.dumps(content_json), 'application/json')
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
                    self.params['file'] = self.params.get('filename')
                    del self.params['filename']
                self.result['status'] = auth['status']
                self.module.fail_json(msg=json.loads(
                    auth.get('body'))['messages'][0]['message'], **self.result)

            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']

            self.result['Result'] = "Pre-change analysis %(name)s successfully created." % self.params

        elif '5.0' in self.version or '5.1' in self.version:
            form = {
                "name": self.params.get('name'),
                "description": self.params.get('description'),
                "allow_unsupported_object_modification": True,
                "stop_analysis": False,
                "fabric_uuid": self.params.get('fabric_id'),
                "base_epoch_id": self.params.get('base_epoch_id'),
                "imdata": json.loads(self.params.get('changes'))
            }

            obj = self.get_pre_change_analysis()
            if obj is not None:
                self.params['job_id'] = obj.get('job_id')
                if not self.issubset(form, obj):
                    if obj.get('analysis_status') != 'SAVED':
                        self.module.fail_json(
                            msg='Pre-change analysis {0} is not in SAVED status. It cannot be edited.'.format(self.params.get('name')),
                            **self.result)
                    else:
                        if self.params.get('action') == 'SAVE':
                            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/manual-changes/%(job_id)s?action=SAVE' % self.params
                            method = 'PUT'
                        else:
                            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/manual-changes/%(job_id)s?action=RUN' % self.params
                            method = 'PUT'
                else:
                    url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/manual-changes/%(job_id)s?action=RUN' % self.params
                    method = 'PUT'
            else:
                self.result['Previous'] = {}
                url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/prechange-analysis/manual-changes?action=%(action)s' % self.params
                method = 'POST'

            if not self.issubset(form, obj) or (obj.get('analysis_status') == 'SAVED' and self.params.get('action') == 'RUN'):
                resp, auth = fetch_url(self.module, url,
                                       headers=self.http_headers,
                                       data=json.dumps(form),
                                       method=method)

                if auth.get('status') != 200:
                    if('filename' in self.params):
                        self.params['file'] = self.params.get('filename')
                        del self.params['filename']
                    self.result['status'] = auth['status']
                    self.module.fail_json(msg=json.loads(
                        auth.get('body'))['messages'][0]['message'], **self.result)

                if('filename' in self.params):
                    self.params['file'] = self.params.get('filename')
                    del self.params['filename']

                self.result['Result'] = "Pre-change analysis %(name)s successfully created." % self.params
                self.result['changed'] = True

    def issubset(self, subset, superset):
        ''' Recurse through nested dictionary and compare entries '''

        # Both objects are the same object
        if subset is superset:
            return True

        # Both objects are identical
        if subset == superset:
            return True

        # Both objects have a different type
        if type(subset) != type(superset):
            return False

        for key, value in subset.items():
            # Ignore empty values
            if value is None:
                return True

            # Item from subset is missing from superset
            if key not in superset:
                return False

            # Item has different types in subset and superset
            if type(superset.get(key)) != type(value):
                return False

            # Compare if key & values are similar to subset
            if not all(superset.get(key, None) == val for key, val in subset.items()):
                return False

            # Compare if item values are subset
            if isinstance(value, dict):
                if not self.issubset(superset.get(key), value):
                    return False
            elif isinstance(value, set):
                if not value <= superset.get(key):
                    return False
            else:
                if not value == superset.get(key):
                    return False

        return True

    def create_pre_change_from_file(self):
        if not os.path.exists(self.params.get('file')):
            self.module.fail_json(
                msg="File not found : {0}".format(self.params.get('file')),
                **self.result)
        filename = self.params.get('file')
        self.params['filename'] = filename
        f = open(self.params.get('file'), "rb")
        if self.is_json(f.read()) is False:
            if self.params.get('verify'):
                # # Input file is not parsed.
                self.params['cmap'] = {}
                data = self.load(open(self.params.get('file')))
                tree = self.construct_tree(data)
                if tree is False:
                    self.module.fail_json(
                        msg="Error parsing input file, unsupported object found in hierarchy.",
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
            else:
                self.module.fail_json(
                    msg="Error parsing input file. JSON format necessary",
                    **self.result)
        config = []
        self.params['file'] = f
        self.params['changes'] = config
        self.send_pre_change_payload()

    def copy_children(self, tree):
        '''
        Copies existing children objects to the built tree
        '''
        cmap = self.params.get('cmap')
        for dn, children in cmap.items():
            aci_class = self.get_aci_class(
                (self.parse_path(dn)[-1]).split("-")[0])
            json_path_expr_search = parse('$..children.[*].{0}'.format(aci_class))
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
                    buffer += c[i + 1]
                    i += 1

                if depth == 0:
                    if len(buffer.strip()) > 0:
                        j = json.loads(buffer)
                        if not isinstance(j, list):
                            raise AssertionError("")
                        items += j
                    buffer = ""

                i += 1

        if depth != 0:
            raise AssertionError("Error in loading input json")
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
                if 'attributes' not in desc:
                    raise AssertionError("attributes not in desc")
                attr = desc.get('attributes')
                if 'dn' not in attr:
                    raise AssertionError("dn not in desc")
                if 'children' in desc:
                    existing_children = desc.get('children')
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
          - z (data of /z)s
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
        Exports the constructed tree to a hierarchial json representation. (equal to tn-ansible, except for ordering)
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
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.module.fail_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        self.result['msg'] = json.loads(resp.read())['value']['data']

    def get_epochs(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/assured-networks/%(fabric_id)s/epochs?$sort=-collectionTimestamp' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               data=None,
                               method='GET')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.module.fail_json(
                msg=json.loads(
                    auth.get('body'))['messages'][0]['message'],
                **self.result)

        if resp.headers.get('Content-Encoding') == "gzip":
            r = gzip.decompress(resp.read())
            return json.loads(r.decode())['value']['data']
        return json.loads(resp.read())['value']['data']

    def send_pre_change_payload(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
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

        elif '5.0' in self.version or '5.1' in self.version:
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

        # Need to set the right content type for the multi part upload!
        h = self.http_headers.copy()
        h['Content-Type'] = m.content_type

        resp, auth = fetch_url(self.module, url,
                               headers=h,
                               data=m,
                               method='POST')

        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.result['status'] = auth['status']
            self.module.fail_json(msg=json.loads(
                auth.get('body'))['messages'][0]['message'], **self.result)

        if('filename' in self.params):
            self.params['file'] = self.params.get('filename')
            del self.params['filename']

        self.result['Result'] = "Pre-change analysis %(name)s successfully created." % self.params

    def check_existing(self):
        try:
            form = json.loads(self.params.get('form'))
        except Exception:
            self.module.fail_json(msg='The form cannot be loaded properly')
        if form is None:
            self.module.fail_json(msg='The form is empty')
        elif form.get('name') is None:
            self.module.fail_json(msg='The name should not be empty')
        obj, type_map, detail = self.query_compliance_object(form.get('name'))
        return obj, form, detail

    def check_changed(self, previous, current):
        if previous == current:
            self.result['changed'] = False
        else:
            self.result['changed'] = True
        return self.result['changed']

    def new_object_selector(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        obj, form, detail = self.check_existing()
        if obj != []:
            self.result['Previous'] = detail['value']['data']
            url = 'https://{0}:{1}/nae/api/v1/event-services/'\
                  'assured-networks/{2}/model/aci-policy/'\
                  'compliance-requirement/object-selectors/{3}'.format(self.params.get('host'),
                                                                       self.params.get('port'),
                                                                       self.params.get('fabric_uuid'),
                                                                       str(obj[0].get('uuid')))
            method = 'PUT'
            form['uuid'] = obj[0].get('uuid')
            self.params['form'] = json.dumps(form)
        else:
            self.result['Previous'] = {}
            url = 'https://{0}:{1}/nae/api/v1/event-services/'\
                  'assured-networks/{2}/model/aci-policy/'\
                  'compliance-requirement/object-selectors'.format(self.params.get('host'),
                                                                   self.params.get('port'),
                                                                   self.params.get('fabric_uuid'))
            method = 'POST'
        resp, auth = fetch_url(self.module, url,
                               data=json.dumps(form),
                               headers=self.http_headers,
                               method=method)
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=json.loads(auth.get('body'))[
                                      'messages'][0]['message'], **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
            else:
                r = resp.read()
            self.result['Current'] = json.loads(r)['value']['data']
            self.check_changed(self.result['Previous'], self.result['Current'])

    def new_traffic_selector(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        obj, form, detail = self.check_existing()
        if obj != []:
            self.result['Previous'] = detail['value']['data']
            url = 'https://{0}:{1}/nae/api/v1/event-services/'\
                  'assured-networks/{2}/model/aci-policy/'\
                  'compliance-requirement/traffic-selectors/{3}'.format(self.params.get('host'),
                                                                        self.params.get('port'),
                                                                        self.params.get('fabric_uuid'),
                                                                        str(obj[0].get('uuid')))
            method = 'PUT'
            form['uuid'] = obj[0].get('uuid')
            self.params['form'] = json.dumps(form)
        else:
            self.result['Previous'] = {}
            url = 'https://{0}:{1}/nae/api/v1/event-services/' \
                  'assured-networks/{2}/model/aci-policy/' \
                  'compliance-requirement/traffic-selectors'.format(self.params.get('host'),
                                                                    self.params.get('port'),
                                                                    self.params.get('fabric_uuid'))
            method = 'POST'
        resp, auth = fetch_url(self.module, url,
                               data=json.dumps(form),
                               headers=self.http_headers,
                               method=method)
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=json.loads(auth.get('body'))[
                                      'messages'][0]['message'], **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
            else:
                r = resp.read()
            self.result['Current'] = json.loads(r)['value']['data']
            self.check_changed(self.result['Previous'], self.result['Current'])

    def new_compliance_requirement(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        obj, form, detail = self.check_existing()
        if obj != []:
            self.result['Previous'] = detail['value']['data']
            url = 'https://{0}:{1}/nae/api/v1/event-services/'\
                  'assured-networks/{2}/model/aci-policy/'\
                  'compliance-requirement/requirements/{3}'.format(self.params.get('host'),
                                                                   self.params.get('port'),
                                                                   self.params.get('fabric_uuid'),
                                                                   str(obj[0].get('uuid')))
            method = 'PUT'
            form['uuid'] = obj[0].get('uuid')
            self.params['form'] = json.dumps(form)
        else:
            self.result['Previous'] = {}
            url = 'https://{0}:{1}/nae/api/v1/event-services/assured-networks' \
                  '/{2}/model/aci-policy/compliance-requirement/requirements'.format(self.params.get('host'),
                                                                                     self.params.get('port'),
                                                                                     self.params.get('fabric_uuid'))
            method = 'POST'
        resp, auth = fetch_url(self.module, url,
                               data=json.dumps(form),
                               headers=self.http_headers,
                               method=method)
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=json.loads(auth.get('body'))[
                                      'messages'][0]['message'], **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
            else:
                r = resp.read()
            self.result['Current'] = json.loads(r)['value']['data']
            self.check_changed(self.result['Previous'], self.result['Current'])

    def new_compliance_requirement_set(self):
        obj, form, detail = self.check_existing()
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_uuid'] = str(ag.get('uuid'))
        assurance_groups_lists = []
        if self.params.get('association_to_ag'):
            assurance_groups_lists.append(dict(active=self.params.get('active'), fabric_uuid=ag.get('uuid')))
        form['assurance_groups'] = assurance_groups_lists
        if obj == [] and ('5.1' in self.version or '5.0' in self.version):
            url = 'https://{0}:{1}/nae/api/v1/event-services/' \
                  'assured-networks/{2}/model/aci-policy/' \
                  'compliance-requirement/requirement-sets'.format(self.params.get('host'),
                                                                   self.params.get('port'),
                                                                   self.params.get('fabric_uuid'))
        else:
            url = 'https://{0}:{1}/nae/api/v1/event-services/' \
                  'assured-networks/{2}/model/aci-policy/' \
                  'compliance-requirement/requirement-sets/' \
                  '{3}'.format(self.params.get('host'),
                               self.params.get('port'),
                               self.params.get('fabric_uuid'),
                               str(obj[0].get('uuid')))
        if obj != []:
            self.result['Previous'] = detail['value']['data']
            method = 'PUT'
            form['uuid'] = obj[0].get('uuid')
        else:
            self.result['Previous'] = {}
            method = 'POST'
        self.params['form'] = json.dumps(form)
        resp, auth = fetch_url(self.module, url,
                               data=self.params.get('form'),
                               headers=self.http_headers,
                               method=method)
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
            else:
                r = resp.read()
            self.result['Current'] = json.loads(r)['value']['data']
            self.check_changed(self.result.get('Previous'), self.result.get('Current'))

    def get_all_requirement_sets(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/requirement-sets' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='GET')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                self.result['Result'] = json.loads(r.decode())['value']['data']
                return json.loads(r.decode())['value']['data']
            r = resp.read()
            self.result['Result'] = json.loads(r)['value']['data']
            return json.loads(r)['value']['data']

    def get_all_requirements(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/requirements' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='GET')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                self.result['Result'] = json.loads(r.decode())['value']['data']
                return json.loads(r.decode())['value']['data']
            r = resp.read()
            self.result['Result'] = json.loads(r)['value']['data']
            return json.loads(r)['value']['data']

    def get_all_traffic_selectors(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/traffic-selectors' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='GET')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                self.result['Result'] = json.loads(r.decode())['value']['data']
                return json.loads(r.decode())['value']['data']
            r = resp.read()
            self.result['Result'] = json.loads(r)['value']['data']
            return json.loads(r)['value']['data']

    def get_all_object_selectors(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/object-selectors' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='GET')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                self.result['Result'] = json.loads(r.decode())['value']['data']
                return json.loads(r.decode())['value']['data']
            r = resp.read()
            self.result['Result'] = json.loads(r)['value']['data']
            return json.loads(r)['value']['data']

    def get_obj_detail(self, obj, type):
        url_map = {
            'object': 'object-selectors',
            'traffic': 'traffic-selectors',
            'requirement': 'requirements',
            'requirement_set': 'requirement-sets'
        }
        if obj != []:
            try:
                uuid = obj[0].get('uuid')
            except Exception:
                self.module.fail_json(msg="There is no uuid in {0}".format(url_map[type]))
            url = 'https://{0}:{1}/nae/api/v1/event-services/' \
                'assured-networks/{2}/model/aci-policy/' \
                'compliance-requirement/{3}/{4}'.format(self.params.get('host'),
                                                        self.params.get('port'),
                                                        self.params.get('fabric_uuid'),
                                                        url_map[type],
                                                        uuid)
            resp, auth = fetch_url(self.module, url,
                                   headers=self.http_headers,
                                   method='GET')
            if auth.get('status') != 200:
                if('filename' in self.params):
                    self.params['file'] = self.params.get('filename')
                    del self.params['filename']
                self.status = auth.get('status')
                try:
                    self.module.fail_json(msg=auth.get('body'), **self.result)
                except KeyError:
                    # Connection error
                    self.module.fail_json(
                        msg='Connection failed for %(url)s. %(msg)s' %
                        auth, **self.result)
            else:
                if resp.headers.get('Content-Encoding') == "gzip":
                    r = gzip.decompress(resp.read())
                    detail = json.loads(r.decode())
                    return detail
                r = resp.read()
                detail = json.loads(r)
                return detail
        else:
            detail = {}
            return detail

    def query_compliance_object(self, name):
        type_map = {
            'object': 'Object selector',
            'traffic': 'Traffic selector',
            'requirement': 'Requirement',
            'requirement_set': 'Requirement set'
        }
        if self.params.get('selector') == 'object':
            objs = self.get_all_object_selectors()
            obj = [x for x in objs if x['name'] == name]
            detail = self.get_obj_detail(obj, 'object')
        elif self.params.get('selector') == 'traffic':
            objs = self.get_all_traffic_selectors()
            obj = [x for x in objs if x['name'] == name]
            detail = self.get_obj_detail(obj, 'traffic')
        elif self.params.get('selector') == 'requirement':
            objs = self.get_all_requirements()
            obj = [x for x in objs if x['name'] == name]
            detail = self.get_obj_detail(obj, 'requirement')
        elif self.params.get('selector') == 'requirement_set':
            objs = self.get_all_requirement_sets()
            obj = [x for x in objs if x['name'] == name]
            detail = self.get_obj_detail(obj, 'requirement_set')
        return obj, type_map, detail

    def get_compliance_object(self, name):
        obj, type_map, detail = self.query_compliance_object(name)
        if obj != []:
            self.result['Result'] = obj[0]
            return obj[0]
        else:
            self.result['Result'] = []
            self.module.exit_json(
                msg="WARNING: {0} {1} does not exist!!!".format(type_map.get(self.params.get('selector')), self.params.get('name')), **self.result)

    def delete_object_selector(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        self.params['obj_uuid'] = self.get_compliance_object(
            self.params.get('name'))["uuid"]
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/object-selectors/%(obj_uuid)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='DELETE')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            self.result['Result'] = "Object selector " + \
                self.params.get('name') + " deleted"

    def delete_traffic_selector(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        self.params['obj_uuid'] = self.get_compliance_object(self.params.get('name'))["uuid"]
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/traffic-selectors/%(obj_uuid)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='DELETE')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            self.result['Result'] = "Traffic selector " + \
                self.params.get('name') + " deleted"

    def delete_requirement(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        self.params['obj_uuid'] = self.get_compliance_object(
            self.params.get('name'))["uuid"]
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/requirements/%(obj_uuid)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='DELETE')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            self.result['Result'] = "Requirement " + \
                self.params.get('name') + " deleted"

    def delete_requirement_set(self):
        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        self.params['obj_uuid'] = self.get_compliance_object(
            self.params.get('name'))["uuid"]
        url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
              'assured-networks/%(fabric_uuid)s/model/aci-policy/' \
              'compliance-requirement/requirement-sets/%(obj_uuid)s' % self.params
        resp, auth = fetch_url(self.module, url,
                               headers=self.http_headers,
                               method='DELETE')
        if auth.get('status') != 200:
            if('filename' in self.params):
                self.params['file'] = self.params.get('filename')
                del self.params['filename']
            self.status = auth.get('status')
            try:
                self.module.fail_json(msg=auth.get('body'), **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)
        else:
            self.result['Result'] = "Requirement set " + \
                self.params.get('name') + " deleted"

    def getFirstAG(self):
        self.get_all_assurance_groups()
        return self.assuranceGroups[0]

    def upload_file(self):
        for page in self.get_all_files():
            self.params['file_id'] = [f for f in page if f.get('unique_name') == self.params.get('name')]
        if self.params.get('file_id') != []:
            self.module.exit_json(msg="WARNING: file with the same name already exist!!!", **self.result)

        self.params['fabric_uuid'] = self.getFirstAG().get("uuid")
        file_upload_uuid = None
        uri = 'https://%(host)s:%(port)s/nae/api/v1/file-services/upload-file' % self.params
        try:
            with self.get_logout_lock():
                chunk_url = self.start_upload(uri, 'OFFLINE_ANALYSIS')
                complete_url = None
                if chunk_url:
                    complete_url = self.upload_file_by_chunk(chunk_url)
                else:
                    self.module.fail_json(msg='Error', **self.result)
                if complete_url:
                    file_upload_uuid = self.complete_upload(complete_url)
                else:
                    self.module.fail_json(
                        'Failed to upload file chunks', **self.result)
            return file_upload_uuid
        except Exception as e:
            self.module.fail_json(msg='Failed to upload file chunks', **self.result)

    def start_upload(self, uri, upload_type):
        """
        Pass metadata to api and trigger start of upload file.
        Args:
            unique_name: str: name of upload
            file_name:  str:  file name of upload
            file_path:  str: path of file
            fabric_uuid: str: offline fabric id
            uri: str: uri
            upload_type: str: offline file/nat file
        Returns:
            str: chunk url , used for uploading chunks
                  or None if there was an issue starting
        """
        file_size_in_bytes = os.path.getsize(self.params.get('file'))
        file_name = os.path.basename(self.params.get('file'))
        args = {"data": {"comment": "",
                         "unique_name": self.params.get('name'),
                         "filename": file_name,
                         "size_in_bytes": int(file_size_in_bytes),
                         "upload_type": upload_type}}  # "OFFLINE_ANALYSIS"

        resp, auth = fetch_url(self.module, uri,
                               data=json.dumps(args['data']),
                               headers=self.http_headers,
                               method='POST')
        if auth.get('status') == 201:
            return str(json.loads(resp.read())['value']['data']['links'][-1]['href'])
        else:
            self.status = auth.get('status')
            try:
                message = auth.get('body')
                self.module.fail_json(msg=message, **self.result)
            except KeyError:
                # Connection error
                self.module.fail_json(
                    msg='Connection failed for %(url)s. %(msg)s' %
                    auth, **self.result)

        return None

    def upload_file_by_chunk(self, chunk_url):
        """Pass metadata to api and trigger start of upload file.
        Args:
           chunk_url: str: url to send chunks
           file_path: str: path of file and filename
        Returns:
            str: chunk url , used for uploading chunks or None if issue uploading
        """
        try:
            chunk_id = 0
            offset = 0
            chunk_uri = 'https://%(host)s:%(port)s/nae' % self.params
            chunk_uri = chunk_uri + chunk_url[chunk_url.index('/api/'):]
            response = None
            file_size_in_bytes = os.path.getsize(self.params.get('file'))
            chunk_byte_size = 10000000
            if file_size_in_bytes < chunk_byte_size:
                chunk_byte_size = int(file_size_in_bytes // 2)
            with open(self.params.get('file'), 'rb') as f:
                for chunk in self.read_in_chunks(f, chunk_byte_size):
                    checksum = hashlib.md5(chunk).hexdigest()
                    chunk_info = {"offset": int(offset),
                                  "checksum": checksum,
                                  "chunk_id": chunk_id,
                                  "size_in_bytes": sys.getsizeof(chunk)}
                    files = {"chunk-info": (None, json.dumps(chunk_info),
                                            'application/json'),
                             "chunk-data": (os.path.basename(self.params.get('file')) +
                                            str(chunk_id),
                                            chunk, 'application/octet-stream')}
                    args = {"files": files}
                    chunk_headers = self.http_headers.copy()
                    chunk_headers.pop("Content-Type", None)
                    # Ansible prefers us to use fetch_url but does not support binary file uploads
                    # so reverting back to requests seems the only thing not working.
                    response = requests.post(chunk_uri, data=None, files=args.get('files'), headers=chunk_headers, verify=False)
                    chunk_id += 1
                    if response and response.status_code != 201:
                        self.module.fail_json(
                            msg="Incorrect response code", **self.result)
                        return None
                if response:
                    return str(response.json()['value']['data']['links'][-1]['href'])
                else:
                    self.module.fail_json(
                        msg="No response received while uploading chunks", **self.result)
        except IOError as ioex:
            self.module.fail_json(
                msg="Cannot open supplied file", **self.result)
        return None

    def read_in_chunks(self, file_object, chunk_byte_size):
        """
        Return chunks of file.
        Args:
           file_object: file: open file object
           chunk_byte_size: int: size of chunk to return
        Returns:
            Returns a chunk of the file
        """
        while True:
            data = file_object.read(chunk_byte_size)
            if not data:
                break
            yield data

    def complete_upload(self, complete_url):
        """Complete request to start dag.
        Args:
           chunk_url: str: url to complete upload and start dag
        Returns:
            str: uuid or None
        NOTE: Modified function to not fail if epoch is at scale.
        Scale epochs sometimes take longer to upload and in that
        case, the api returns a timeout even though the upload
        completes successfully later.
        """
        timeout = 300
        complete_uri = 'https://%(host)s:%(port)s/nae' % self.params
        complete_uri = complete_uri + \
            complete_url[complete_url.index('/api/'):]
        resp, auth = fetch_url(self.module, complete_uri,
                               data=None,
                               headers=self.http_headers,
                               method='POST')
        try:
            if resp and auth.get('status') == 200:
                return str(json.loads(resp.read())['value']['data']['links'][-1]['href'])
            elif not resp or auth.get('status') == 400:
                total_time = 0
                while total_time < timeout:
                    time.sleep(10)
                    total_time += 10
                    resp, auth = fetch_url(
                        self.module, 'https://%(host)s:%(port)s/nae/api/v1/file-services/upload-file', data=None, method='GET')
                    if resp and auth.get('status') == 200:
                        json.loads(resp.read())
                        uuid = complete_url.split('/')[-2]
                        for offline_file in resp['value']['data']:
                            if offline_file['uuid'] == uuid:
                                success = offline_file['status'] == 'UPLOAD_COMPLETED'
                                if success:
                                    return {'uuid': offline_file['uuid']}

            self.module.fail_json(msg="No upload complete", **self.result)
            raise Exception
        except Exception as e:
            self.module.fail_json(msg="Unknown error", **self.result)

    def isLiveAnalysis(self):
        self.get_all_assurance_groups()
        for ag in self.assuranceGroups:
            if ag['status'] == "RUNNING" and 'iterations' not in ag:
                return ag['unique_name']

    def isOnDemandAnalysis(self):
        self.get_all_assurance_groups()
        for ag in self.assuranceGroups:
            if (ag['status'] == "RUNNING" or ag['status'] == "ANALYSIS_NOT_STARTED" or ag['status'] == "ANALYSIS_IN_PROGRESS") and ('iterations' in ag):
                return ag['unique_name']

    def get_tcam_stats(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        self.params['latest_epoch'] = str(self.get_epochs()[-1]["epoch_id"])
        self.params['page'] = 0
        self.params['obj_per_page'] = 200
        has_more_data = True
        tcam_data = []
        # As long as there is more data get it
        while has_more_data:
            # I get data sorter by tcam hists for hitcount-by-rules --> hitcount-by-epgpair-contract-filter
            url = 'https://%(host)s:%(port)s/nae/api/v1/event-services/' \
                  'assured-networks/%(fabric_id)s/model/aci-policy/tcam/' \
                  'hitcount-by-rules/hitcount-by-epgpair-contract-filter' \
                  '?$epoch_id=%(latest_epoch)s&$page=%(page)s&$sort=-cumulative_count&$view=histogram' % self.params
            resp, auth = fetch_url(
                self.module, url, headers=self.http_headers, method='GET')
            if auth.get('status') != 200:
                self.result['Error'] = auth.get('msg')
                self.result['url'] = url
                self.module.fail_json(msg="Error getting TCAM", **self.result)
            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                has_more_data = json.loads(r.decode())[
                    'value']['data_summary']['has_more_data']
                tcam_data.append(json.loads(r.decode())['value']['data'])
            else:
                has_more_data = json.loads(resp.read())[
                    'value']['data_summary']['has_more_data']
                tcam_data.append(json.loads(resp.read())['value']['data'])
            self.params['page'] = self.params.get('page') + 1

        self.result['Result'] = 'Pages extracted %(page)s ' % self.params
        return tcam_data

    def tcam_to_csv(self):
        tcam_data = self.get_tcam_stats()
        tcam_stats = []
        for page in tcam_data:
            for item in page:
                tdic = {}
                for key, value in item.items():
                    if key == "bucket":
                        tdic['Provider EPG'] = value['provider_epg']['dn'].replace(
                            "uni/", "")
                        tdic['Consumer VRF'] = value['consumer_vrf']['dn'].replace(
                            "uni/", "")
                        tdic['Consumer EPG'] = value['consumer_epg']['dn'].replace(
                            "uni/", "")
                        tdic['Contract'] = value['contract']['dn'].replace(
                            "uni/", "")
                        tdic['Filter'] = value['filter']['dn'].replace(
                            "uni/", "")
                    if key == "output":
                        if 'month_count' in value:
                            tdic["Monthly Hits"] = value['month_count']
                        else:
                            tdic["Monthly Hits"] = "N/A"
                        tdic['Total Hits'] = value['cumulative_count']
                        tdic['TCAM Usage'] = value['tcam_entry_count']
                tcam_stats.append(tdic)
        outfile = self.params.get('file') + '.csv'
        with open(outfile, 'w', newline='') as f:
            fieldnames = ['Provider EPG', 'Consumer EPG', 'Consumer VRF',
                          'Contract', 'Filter', 'Monthly Hits', 'Total Hits', 'TCAM Usage']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for i in tcam_stats:
                writer.writerow(i)
        success = 'to file %(file)s.csv' % self.params
        self.result['msg'] = self.result['Result'] + success
        self.result['changed'] = True

    def StartOnDemandAnalysis(self, iterations):
        runningLive = self.isLiveAnalysis()
        runningOnDemand = self.isOnDemandAnalysis()
        if runningLive:
            self.module.fail_json(
                msg='There is currently a Live analysis on {0} please stop it manually and try again'.format(runningLive), **self.result)

        elif runningOnDemand:
            self.module.fail_json(
                msg='There is currently an OnDemand analysis running on {0} please stop it manually and try again'.format(runningOnDemand), **self.result)
        else:
            ag = self.get_assurance_group(self.params.get('ag_name'))
            if ag is None:
                self.result['Result'] = "No such Assurance Group exists"
                self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
            self.params['fabric_uuid'] = str(ag.get('uuid'))

            ag_iterations = json.dumps({'iterations': iterations})
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/assured-networks/aci-fabric/%(fabric_uuid)s/start-analysis' % self.params
            resp, auth = fetch_url(self.module, url,
                                   data=ag_iterations,
                                   headers=self.http_headers,
                                   method='POST')
            if auth.get('status') == 200:
                self.result[
                    'Result'] = 'Successfully started OnDemand Analysis on %(ag_name)s' % self.params

            else:
                self.module.fail_json(
                    msg="OnDemand Analysis failed to start", **self.result)

    def get_delta_analysis(self):
        ret = self.get_delta_analyses()
        for a in ret:
            if a['unique_name'] == self.params.get('name'):
                # self.result['analysis'] = a
                return a
        return None

    def query_delta_analyses(self):
        self.result['Delta analyses'] = self.get_delta_analyses()

    def get_delta_analyses(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        url = 'https://%(host)s/nae/api/v1/job-services?$page=0&$size=' \
              '100&$sort=status&$type=EPOCH_DELTA_ANALYSIS&assurance_group_id=%(fabric_id)s' % self.params
        resp, auth = fetch_url(self.module, url, data=None,
                               headers=self.http_headers, method='GET')
        return json.loads(resp.read())['value']['data']

    def delete_delta_analysis(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        self.params['fabric_id'] = str(ag.get('uuid'))
        try:
            self.params['analysis_id'] = [analysis for analysis in self.get_delta_analyses(
            ) if analysis['unique_name'] == self.params.get('name')][0]['uuid']
        except IndexError:
            fail = "Delta analysis %(name)s does not exist on %(ag_name)s." % self.params
            self.module.fail_json(msg=fail, **self.result)

        url = 'https://%(host)s/nae/api/v1/job-services/%(analysis_id)s' % self.params
        resp, auth = fetch_url(self.module, url, data=None,
                               headers=self.http_headers, method='DELETE')
        if 'OK' in auth.get('msg'):
            self.result['Result'] = 'Delta analysis %(name)s successfully deleted' % self.params
        else:
            fail = "Delta analysis deleted failed " + auth.get('msg')
            self.module.fail_json(msg=fail, **self.result)

    def new_delta_analysis(self):
        ag = self.get_assurance_group(self.params.get('ag_name'))
        if ag is None:
            self.result['Result'] = "No such Assurance Group exists"
            self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
        fabric_id = str(ag.get('uuid'))
        epochs = list(self.get_epochs())
        e = [epoch for epoch in epochs if epoch['fabric_id'] == fabric_id]
        later_epoch_uuid = e[0]['epoch_id']
        prior_epoch_uuid = e[1]['epoch_id']
        url = 'https://%(host)s/nae/api/v1/job-services' % self.params
        form = '''{
               "type": "EPOCH_DELTA_ANALYSIS",
               "name": "''' + self.params.get('name') + '''",
               "parameters": [
                   {
                       "name": "prior_epoch_uuid",
                       "value": "''' + str(prior_epoch_uuid) + '''"
                   },
                   {
                       "name": "later_epoch_uuid",
                       "value": "''' + str(later_epoch_uuid) + '''"
                   }
                   ]
               }'''
        resp, auth = fetch_url(self.module, url, data=form,
                               headers=self.http_headers, method='POST')

        if 'OK' in auth.get('msg'):
            self.result['Result'] = 'Delta analysis %(name)s successfully created' % self.params
        else:
            fail = "Delta analysis creation failed " + auth.get('msg')
            self.module.fail_json(msg=fail, **self.result)

    def get_all_files(self):
        has_more_data = True
        while has_more_data:
            url = 'https://%(host)s:%(port)s/nae/api/v1/file-services/upload-file' % self.params
            resp, auth = fetch_url(self.module, url,
                                   headers=self.http_headers,
                                   data=None,
                                   method='GET')

            if auth.get('status') != 200:
                if('filename' in self.params):
                    self.params['file'] = self.params.get('filename')
                    del self.params['filename']
                self.module.fail_json(
                    msg=json.loads(
                        auth.get('body'))['messages'][0]['message'],
                    **self.result)

            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                has_more_data = json.loads(r.decode())['value']['data_summary']['has_more_data']
                self.files.append(json.loads(r.decode())['value']['data'])
            else:
                r = resp.read()
                has_more_data = json.loads(r)['value']['data_summary']['has_more_data']
                self.files.append(json.loads(r)['value']['data'])
            return self.files

    def delete_file(self):
        try:
            for page in self.get_all_files():
                self.params['file_id'] = [f for f in page if f['unique_name'] == self.params.get('name')][0]['uuid']

        except IndexError:
            fail = "File %(name)s does not exist on." % self.params
            self.module.fail_json(msg=fail, **self.result)
        url = 'https://%(host)s/nae/api/v1/file-services/upload-file/%(file_id)s' % self.params
        resp, auth = fetch_url(self.module, url, data=None,
                               headers=self.http_headers, method='DELETE')
        if 'OK' in auth.get('msg'):
            self.result['Result'] = 'File %(name)s successfully deleted' % self.params
        else:
            fail = "File  deleted failed " + auth.get('msg')
            self.module.fail_json(msg=fail, **self.result)

    def newOfflineAnalysis(self):
        if self.isOnDemandAnalysis() or self.isLiveAnalysis():
            self.module.fail_json(msg="There is currently an  analysis running.", **self.result)

        if self.get_OfflineAnalysis(self.params.get('name')):
            self.result['Result'] = 'Offline Analysis %(name)s elready exists ' % self.params
        else:
            self.get_all_files()
            for uploadedFile in self.files:
                fileID = [f for f in uploadedFile if f.get('unique_name') == self.params.get('filename')]
                if not fileID:
                    self.module.fail_json(msg="File %(filename)s not found" % self.params, **self.result)
            fileID = fileID[0]['uuid']
            ag = self.get_assurance_group(self.params.get('ag_name'))
            if ag is None:
                self.result['Result'] = "No such Assurance Group exists"
                self.module.fail_json(msg='Assurance group {0} does not exist'.format(self.params.get('ag_name')), **self.result)
            fabricID = str(ag.get('uuid'))
            form = '''{
            "unique_name": "''' + self.params.get('name') + '''",
            "file_upload_uuid": "''' + fileID + '''",
            "aci_fabric_uuid": "''' + fabricID + '''",
            "analysis_timeout_in_secs": 3600
            }'''
            if '4.1' in self.version or '5.0' in self.version or '5.1' in self.version:
                # in 4.1 starting an offline analysis is composed of 2 steps
                # 1 Create the Offline analysis
                url = 'https://%(host)s/nae/api/v1/config-services/offline-analysis' % self.params

                resp, auth = fetch_url(self.module, url, data=form,
                                       headers=self.http_headers, method='POST')

                if auth.get('status') == 202:
                    # Get the analysis UUID:
                    analysis_id = json.loads(resp.read())['value']['data']['uuid']

                    url = 'https://%(host)s/nae/api/v1/config-services/analysis' % self.params

                    form = '''{
                    "interval": 300,
                    "type": "OFFLINE",
                    "assurance_group_list": [
                    {
                    "uuid": "''' + fabricID + '''"
                    }
                    ],
                    "offline_analysis_list": [
                    {
                    "uuid":"''' + analysis_id + '''"
                    }
                    ],
                    "iterations": 1
                    }'''
                    resp, auth = fetch_url(self.module, url, data=form,
                                           headers=self.http_headers, method='POST')
                    if auth.get('status') == 202 or auth.get('status') == 200:
                        self.result['Result'] = 'Offline Analysis %(name)s successfully created' % self.params
                        if self.params.get('complete') is not None:
                            status = None
                            while status != "ANALYSIS_COMPLETED":
                                status = self.get_OfflineAnalysis(self.params.get('name'))['status']
                                time.sleep(10)
                else:
                    fail = json.loads(auth.get('body'))['messages'][0]['message']
                    self.module.fail_json(msg=fail, **self.result)
            else:
                self.module.fail_json(msg="Unsupported version", **self.result)

    def get_all_OfflineAnalysis(self):
        self.offlineAnalysis.clear()
        has_more_data = True
        while has_more_data:
            url = 'https://%(host)s:%(port)s/nae/api/v1/config-services/offline-analysis' % self.params
            resp, auth = fetch_url(self.module, url,
                                   headers=self.http_headers,
                                   data=None,
                                   method='GET')

            if auth.get('status') != 200:
                if('filename' in self.params):
                    self.params['file'] = self.params.get('filename')
                    del self.params['filename']
                self.module.fail_json(
                    msg=json.loads(
                        auth.get('body'))['messages'][0]['message'],
                    **self.result)

            if resp.headers.get('Content-Encoding') == "gzip":
                r = gzip.decompress(resp.read())
                has_more_data = json.loads(r.decode())['value']['data_summary']['has_more_data']
                self.offlineAnalysis.append(json.loads(r.decode())['value']['data'])
            else:
                r = resp.read()
                has_more_data = json.loads(r)['value']['data_summary']['has_more_data']
                self.offlineAnalysis.append(json.loads(r)['value']['data'])
            return self.offlineAnalysis

    def get_OfflineAnalysis(self, name):
        self.get_all_OfflineAnalysis()
        # To support multiple pages of returned data
        for pages in self.offlineAnalysis:
            for oa in pages:
                if oa.get('unique_name') == name:
                    return oa
        return None

    def deleteOfflineAnalysis(self):
        try:
            for page in self.get_all_OfflineAnalysis():
                self.params['OfflineAnalysisId'] = [f for f in page if f.get('unique_name') == self.params.get('name')][0]['uuid']

        except IndexError:
            fail = "Offline Analysis %(name)s does not exist on." % self.params
            self.module.fail_json(msg=fail, **self.result)
        url = 'https://%(host)s/nae/api/v1/config-services/offline-analysis/%(OfflineAnalysisId)s' % self.params
        resp, auth = fetch_url(self.module, url, data=None,
                               headers=self.http_headers, method='DELETE')
        if 'OK' in auth.get('msg'):
            self.result['Result'] = 'Offline Analysis %(name)s successfully deleted' % self.params
        else:
            fail = "File  deleted failed " + auth.get('msg')
            self.module.fail_json(msg=fail, **self.result)
