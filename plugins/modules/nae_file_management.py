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
module: nae_file_management
short_description: NAE file upload.
description:
- Upload file to NAE.
version_added: '0.0.2'
options:
  name:
    description:
    - Unique name of file upload
    type: str
    aliases: [ unique_name ]
  file:
    description:
    - The absolute path of the file
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
- Shantanu Kulkarni (@shan_kulk)
'''

EXAMPLES = \
    r'''
- name: View all uploaded files
  nae_file_management:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    name: config1
    state: query
- name: Upload file
  nae_file_management:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    state: present
    name: config1
    file: config.tar.gz
- name: Delete Offline/Online Assurance Group
  nae_file_management:
    host: nae
    port: 8080
    username: Admin
    password: 1234
    state: absent
    name: config1
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
        file=dict(type='str', aliases=['file_name']),
        state=dict(type='str', default='present', choices=['absent',
                                                           'present', 'query']),
        validate_certs=dict(type='bool', default=False)
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[['state', 'absent', ['name']],
                                        ['state', 'present', ['file']],
                                        ['state', 'present', ['name']],
                                        ])

    state = module.params.get('state')
    file_name = module.params.get('file')
    name = module.params.get('name')
    nae = NAEModule(module)

    if state == 'present':
        nae.upload_file()
        module.exit_json(**nae.result)
    elif state == 'absent':
        nae.delete_file()
        module.exit_json(**nae.result)
    elif state == 'query':
        nae.get_all_files()
        nae.result['Result'] = nae.files
        module.exit_json(**nae.result)

    module.fail_json(msg='Incorrect params passed', **nae.result)


if __name__ == '__main__':
    main()
