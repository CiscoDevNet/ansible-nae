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
module: nae_tcam
short_description: Export tcam stats as csv.
description:
- Manage compliance objects  on Cisco NAE fabrics.
version_added: '2.4'
options:
  ag_name:
    description:
    - Name of assurance group
    type: str
    required: yes
  file:
    description:
    - Path to file to write tcam data to (csv)
    type: str
    required: no
author:
- Shantanu Kulkarni (@shan_kulk)
'''

EXAMPLES = \
    r'''
- name: Get tcam results
  nae_tcam:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    ag_name: fab1
- name: Get tcam results and write to local csv file
    host: nae
    port: 8080
    username: Admin
    password: 1234
    ag_name: fab1
    file: tcam_data
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
        validate_certs=dict(type='bool', default=False),
        file=dict(type='str', default=""),
        ag_name=dict(type='str', default="")
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    file = module.params.get('file')
    ag_name = module.params.get('ag_name')
    nae = NAEModule(module)
    if ag_name and file:
        nae.tcam_to_csv()
        module.exit_json(**nae.result)
    if ag_name:
        nae.result['tcam'] = nae.get_tcam_stats()
        module.exit_json(**nae.result)
    module.fail_json(msg='Incorrect params passed', **nae.result)


if __name__ == '__main__':
    main()
