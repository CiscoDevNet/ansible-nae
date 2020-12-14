#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = \
    r'''
---
module: nae_prechange
short_description: Manage pre-change analyses.
description:
- Manage Pre-Change Analyses on Cisco NAE fabrics.
version_added: '0.0.2'
options:
  ag_name:
    description:
    - The name of the assurance group.
    type: str
    required: yes
    aliases: [ fab_name ]
  name:
    description:
    - The name of the pre-change analysis
    type: str
    required: yes
  description:
    description:
    - Description for the pre-change analysis.
    type: str
    aliases: [ descr ]
  verify:
    description:
    - When used with C(present) this flag specify if pre-change analysis is made from cisco.aci collection
    - output_path config dump.
    - When used with C(query) this flag will wait to execute the query until the prechange status is COMPLETED.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  file:
    description:
    - Optional parameter if creating new pre-change analysis from file.
  changes:
    description:
    - Optional parameter if creating new pre-change analysis from change-list (manual)
  ignore_sm:
    description:
    - Optional list of Smart Event Mnemonics that should be ignored
    type: list

author:
- Shantanu Kulkarni (@shan_kulk)
- Anvitha Jain (@anvitha-jain)
'''

EXAMPLES = r'''
- name: Add a pre-change analysis from manual changes (version <= 4.1)
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    changes: {"tenant_change": {"action": "ADD","dn": "uni/tn-newTenant","description": "Adding a new Tenant"}}
    name: NewAnalysis
    state: present
  delegate_to: localhost
- name: Add a pre-change analysis from manual changes (version >= 5.0)
  nae_prechange: &add_prechange
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    changes: |
        [
            {
                "vzBrCP": {
                    "attributes": {
                        "descr": "",
                        "intent": "install",
                        "nameAlias": "",
                        "prio": "unspecified",
                        "scope": "context",
                        "targetDscp": "unspecified",
                        "dn": "uni/tn-AnsibleTest/brc-test_brc",
                        "name": "test_brc",
                        "pcv_status": "created"
                    },
                    "children": []
                }
            }
        ]
    name: NewAnalysis
    state: present
  delegate_to: localhost
- name: Delete a pre_change analysis
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    name: NewAnalysis
    state: absent
  delegate_to: localhost
- name: Add a new pre-change analysis from file (JSON from APIC file)
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    file: object_from_apic.json
    name: NewAnalysis
    description: New Analysis
    state: present
  delegate_to: localhost
- name: Add a new pre-change analysis from file (JSON from ACI collection output_path)
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    file: object_from_cisco_aci_collection_output.json
    name: NewAnalysis
    description: New Analysis
    verify: True
    state: present
  delegate_to: localhost
- name: Query a pre-change analysis (wait until status = COMPLETED)
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    name: Analysis1
    state: query
    verify: True
  delegate_to: localhost
- name: Query a pre-change analysis
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    name: Analysis1
    state: query
  delegate_to: localhost
- name: Query a pre-change analysis and ignore some smart_events
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    name: Analysis1
    state: query
    ignore_sm:
      - APP_EPG_NOT_DEPLOYED
      - APP_EPG_HAS_NO_CONTRACT_IN_ENFORCED_VRF
  delegate_to: localhost
- name: Query all pre-change analyses
  nae_prechange:
    host: nae
    port: 8080
    username: Admin
    password: C@ndidadmin1234
    ag_name: FAB2
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = \
    '''
resp:
    description: Return payload
    type: str
    returned: always
'''

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from ansible_collections.cisco.nae.plugins.module_utils.nae import NAEModule, nae_argument_spec
from ansible.module_utils.basic import AnsibleModule
import requests


def main():
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    result = dict(changed=False, resp='')
    argument_spec = nae_argument_spec()
    argument_spec.update(  # Not required for querying all objects
        ag_name=dict(type='str', aliases=['fab_name']),
        name=dict(type='str'),
        description=dict(type='str'),
        changes=dict(type='str'),
        ignore_sm=dict(type='list', default=[]),
        verify=dict(type='bool', default=False),
        save=dict(type='bool', default=False),
        file=dict(type='str', default=None),
        validate_certs=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['absent',
                                                           'present', 'query']),
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[['state', 'absent', ['name']],
                                        ['state', 'present', ['name']]])

    changes = module.params.get('changes')
    change_file = module.params.get('file')
    description = module.params.get('description')
    state = module.params.get('state')
    ag_name = module.params.get('ag_name')
    name = module.params.get('name')
    save = module.params.get('save')
    nae = NAEModule(module)

    module.params['action'] = 'RUN'
    if save:
        module.params['action'] = 'SAVE'

    if state == 'present' and change_file:
        nae.create_pre_change_from_file()
        nae.result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'present' and changes:
        nae.create_pre_change_from_manual_changes()
        module.exit_json(**nae.result)
    elif state == 'query' and name:
        nae.result['Result'] = nae.get_pre_change_result()
        if not nae.result['Result']:
            module.exit_json(
                msg="Pre-change analysis failed. The above smart events have been detected for later epoch only.",
                **nae.result)
        module.exit_json(**nae.result)
    elif state == 'query' and not name:
        nae.show_pre_change_analyses()
        module.exit_json(**nae.result)
    elif state == 'absent':
        nae.delete_pre_change_analysis()
        module.exit_json(**nae.result)

    module.fail_json(msg='Incorrect params passed', **nae.result)


if __name__ == '__main__':
    main()
