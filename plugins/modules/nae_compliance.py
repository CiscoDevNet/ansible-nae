#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from ansible_collections.cisco.nae.plugins.module_utils.nae import NAEModule, nae_argument_spec
from ansible.module_utils.basic import AnsibleModule
import requests
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = \
    r'''
---
module: nae_compliance
short_description: Manage compliance objects.
description:
- Manage compliance objects  on Cisco NAE fabrics.
version_added: '2.4'
options:
  form:
    description:
    - Pre formatted input form for compliance object.
    type: str
    required: no
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(modify) when editing config.
    type: str
    choices: [ absent, present, query, modify ]
    default: present

author:
- Shantanu Kulkarni (@shan_kulk)
'''

EXAMPLES = \
    r'''
- name: Create object selector from form
  nae_compliance:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    state: present
    form: |
      {
    "name": "DataBase",
    "description": null,
    "includes": [
      {
        "matches": [
          {
            "application_epgmatch": {
              "object_attribute": "DN",
              "tenant": {
                "pattern": "NAE_Compliance",
                "type": "EXACT"
              },
              "application_profile": {
                "pattern": "ComplianceIsGood",
                "type": "EXACT"
              },
              "application_epg": {
                "pattern": "DataBase",
                "type": "EXACT"
              }
            }
          }
        ]
      }
    ],
    "excludes": [],
    "selector_type": "OST_EPG"
  }

'''

RETURN = \
    '''
resp:
    description: Return payload
    type: str
    returned: always
'''

def main():
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    result = dict(changed=False, resp='')
    argument_spec = nae_argument_spec()
    argument_spec.update(  # Not required for querying all objects
        name=dict(type='str', aliases=['name']),
        description=dict(type='str'),
        selector=dict(type='str',default='object', choices=['object','traffic','requirement','requirement_set']),
        validate_certs=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['absent',
                                                           'present', 'query', 'modify']),
        form=dict(type='str',default=""),
        ag_name=dict(type='str',default="")
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[['state', 'absent', ['name']],
                                        ['selector', 'requirement_set', ['ag_name']],    
                                        ])
    selector = module.params.get('selector')
    ag_name = module.params.get('ag_name')
    name = module.params.get('name')
    state = module.params.get('state')
    form = module.params.get('form')
    nae = NAEModule(module)
    if state == 'present' and form and selector == 'object':
        nae.new_object_selector()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'present' and form and selector == 'traffic':
        nae.new_traffic_selector()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'present' and form and selector == 'requirement':
        nae.new_compliance_requirement()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'present' and form and selector == 'requirement_set':
        nae.new_compliance_requirement_set()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'query' and selector == 'object':
        nae.get_all_object_selectors()
        module.exit_json(**nae.result)
    elif state == 'query' and selector == 'traffic':
        nae.get_all_traffic_selectors()
        module.exit_json(**nae.result)
    elif state == 'query' and selector == 'requirement':
        nae.get_all_requirements()
        module.exit_json(**nae.result)
    elif state == 'query' and selector == 'requirement_set':
        nae.get_all_requirement_sets()
        module.exit_json(**nae.result)
    elif state == 'absent' and selector == 'object':
        nae.delete_object_selector()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'absent' and selector == 'traffic':
        nae.delete_traffic_selector()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'absent' and selector == 'requirement':
        nae.delete_requirement()
        result['changed'] = True
        module.exit_json(**nae.result)
    elif state == 'absent' and selector == 'requirement_set':
        nae.delete_requirement_set()
        result['changed'] = True
        module.exit_json(**nae.result)
    module.fail_json(msg='Incorrect params passed', **self.result)


if __name__ == '__main__':
    main()
