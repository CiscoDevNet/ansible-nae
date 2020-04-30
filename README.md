# ansible-nae

The ansible-nae project provides an Ansible collection for managing and automating your Cisco NAE environment. It consists of a set of modules and roles for performing tasks related to NAE.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements
Ansible v2.8 or newer

## Install
Ansible must be installed
```
sudo pip install ansible
```

## Use
Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

```
- name: NAE Testing
  hosts: all
  vars:
    nae_login: &nae_login
        host: 1.1.1.1
        port: 443  
        username: Admin
        password: password  
    validate_certs: False
  tasks:
  - name: Create a pre-change analysis from file
    nae_prechange:
      <<: *nae_login
      ag_name: FAB2
      file: config.json
      name: New
      state: present
...
```
