# ansible-nae

The ansible-nae project provides an Ansible collection for managing and automating your Cisco NAE environment. It consists of a set of modules and roles for performing tasks related to NAE.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements
Ansible v2.8 or newer
requests
requests_toolbelt
jsonpath_ng

## Install
Ansible and other requirements must be installed
```
sudo pip install ansible requests requests-toolbelt jsonpath_ng pathlib filelock
```

Install the collection
```
ansible-galaxy collection install cisco.nae
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
  - name Create Online Assurance Group (with APIC Configuration Export Polciy)
    nae_ag:
      <<: *nae_login
      state: present
      name: AG1
      online: True
      apic_hostnames: 1.2.3.4
      apic_username: admin
      apic_password: password
...
```
## RoadMap
### Pre-change analysis
- [x] Configure PCA
- [x] Start/Stop/Query PCA

### Epoch Delta
- [x] Configure Delta Analysis
- [x] Query Delta Analysis Result 

### Compliance Analysis
- [x] Create/Update/Read/Delete
- - [x] Object Selectors
- - [x] Traffic Selector
- - [x] Compliance Requirement 
- - [x] Compliance Requirement Sets 
- [ ] Create Associate/Disassociate a requirement set with an AG
- [ ] Report Creation

### Assurance Group Management
- [x] Create/Update/Read/Delete Online Assurance Group 
- - [ ] Configure F5 Load Balancer
- [x] Create/Update/Read/Delete Offline Assurance Group 

### Offline File Management
- [x] Upload/Delete/Get a File

### Online/Offline Analysis
- [x] Create/Start/Stop/Delete Online Analysis
- [x] Create/Start/Stop/Delete Offline Analysis

### Smart Events
- [ ] Get smart events by Type/Severity 
- [ ] Export Smart Events in CSV format
- [ ] Smart Event Suppression
- - [ ] Create/Update/Delete/Read Even suppression rules
- - [ ] Create/Update/Delete/Read Even suppression rules sets
- - [ ] Activate a rules	 set with an AG
- - [ ] Associate/Disassociate a requirement set with an AG
### TCAM Analysis
- [x] Export TCAM stats as CSV

### Appliance Management
- [ ] Create/Update/Delete/Read Users

# Testing latest code

If you wanna test the latest code you can:
- Clone this repo
- ansible-galaxy collection build --force
- ansible-galaxy collection install cisco-nae-* --force


