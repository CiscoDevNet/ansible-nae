#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = \
    r'''
---
module: nae_offline_analysis
short_description: NAE offline analysis.
description:
- Upload file to NAE.
version_added: '0.0.2'
options:
  name:
    description:
    - Unique name of offline analysis
    type: str
    aliases: [ unique_name ]
  filename:
    description:
    - The uploaded file name
    type: str
    aliases: [ file_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query]
    default: present

author:
- Camillo Rossi (@camrossi)
'''

EXAMPLES = \
    r'''
- name: View offline anaylisis
  nae_offline_analysis:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    name: config1
    state: query
- name: Create offline anaylisis
  nae_offline_analysis:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    state: present
    name: OfflineAnalysis_1
    ag_name: Assurance_Group_1
    filename: OfflineCollection_1
- name: Delete Offline/Online Assurance Group
  nae_offline_analysis:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    state: absent
    name: OfflineAnalysis_1
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
        name=dict(type='str', aliases=['unique_name']),
        filename=dict(type='str', aliases=['file_name']),
        ag_name=dict(type='str', aliases=['assurance_group_name']),
        complete=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['absent',
                                                           'present', 'query', 'complete']),
        validate_certs=dict(type='bool', default=False)
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[['state', 'absent', ['name']],
                                        ['state', 'present', ['filename']],
                                        ['state', 'present', ['name']],
                                        ['state', 'present', ['ag_name']],
                                        ])

    state = module.params.get('state')
    file_name = module.params.get('file')
    name = module.params.get('name')
    ag_name = module.params.get('ag_name')
    nae = NAEModule(module)

    if state == 'present':
        nae.newOfflineAnalysis()
        module.exit_json(**nae.result)
    elif state == 'absent':
        nae.deleteOfflineAnalysis()
        module.exit_json(**nae.result)
    elif state == 'query' and name:
        nae.result['Result'] = nae.get_OfflineAnalysis(name)
        module.exit_json(**nae.result)
    elif state == 'query':
        nae.get_all_OfflineAnalysis()
        nae.result['Result'] = nae.offlineAnalysis
        module.exit_json(**nae.result)

    module.fail_json(msg='Incorrect params passed', **nae.result)


if __name__ == '__main__':
    main()
