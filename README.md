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
## RoadMap
### Pre-change analysis
- [x] Configure PCA
- [x] Start/Stop/Query PCA

### Compliance Analysis
- [ ] Create/Update/Read/Delete
- - [ ] Object Selectors
- - [ ] Traffic Selector
- - [ ] Compiace Requirement 
- - [ ] Compliance Requirement Sets 
- [ ] Create Associate/Disassociate a requirement set with an AG
- [ ] Report Creation

### Assurange Group Management
- [ ] Create/Update/Read/Delete Online Assurange Group 
- - [ ] Configure F5 Load Balancer
- [ ] Create/Update/Read/Delete Offline Assurange Group 

### Offline File Management
- [ ] Upload/Delete/Get a File

### Offline Analysis
- [ ] Create/Start/Stop/Delete Offline Analysis

### Smart Events
- [ ] Get smart events by Type/Severity 
- [ ] Export Smart Events in CSV format
- [ ] Smart Event Suppression
- - [ ] Create/Update/Delete/Read Even suppression rules
- - [ ] Activate a requirement set with an AG
- - [ ] Associate/Disassociate a requirement set with an AG
### TCAM Analysis
- [ ] Export TCAM stats as CSV

### Appliance Management
- [ ] Create/Update/Delete/Read Users


