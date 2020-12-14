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
module: nae_delta
short_description: Delta analysis on Cisco NAE fabrics.
description:
- Manage Delta analyses on Cisco NAE fabrics.
version_added: '0.0.2'
options:
  ag_name:
    description:
    - Name of assurance group
    type: str
    required: yes
  name:
    description:
    - The name of the delta analysis
    type: str
    required: yes
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
author:
- Shantanu Kulkarni (@shan_kulk)
'''

EXAMPLES = \
    r'''
- name: Create delta analysis from two most recent epochs
  nae_delta:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    ag_name: fab1
    name: Delta_Analysis_1
    state: present
- name: Query delta analysis results
  nae_delta:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    ag_name: fab1
    state: query
    name: Delta_Analysis_1
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
        validate_certs=dict(type='bool', default=False),
        name=dict(type='str', default=""),
        ag_name=dict(type='str', default=""),
        state=dict(type='str', default="")
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[['state', 'absent', ['ag_name', 'name']],
                                        ['state', 'query', ['ag_name']],
                                        ['state', 'present', ['ag_name', 'name']]])
    ag_name = module.params.get('ag_name')
    name = module.params.get('name')
    state = module.params.get('state')
    nae = NAEModule(module)
    if state == 'present' and 'name':
        nae.new_delta_analysis()
        module.exit_json(**nae.result)
    if state == 'query' and not name:
        nae.query_delta_analyses()
        module.exit_json(**nae.result)
    if state == 'query' and name:
        nae.result['Result'] = nae.get_delta_result()
        if not nae.result['Result']:
            module.exit_json(
                msg="Delta analysis failed. The above smart events have been detected for later epoch only.",
                **nae.result)
        module.exit_json(**nae.result)
    if state == 'absent':
        nae.delete_delta_analysis()
        module.exit_json(**nae.result)
    module.fail_json(msg='Incorrect params passed', **nae.result)


if __name__ == '__main__':
    main()
