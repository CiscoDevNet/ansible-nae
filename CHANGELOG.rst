==========================================
Cisco NAE Ansible Collection Release Notes
==========================================

.. contents:: Topics

This changelog describes changes after version 0.0.1.

v1.0.0
======

Release Summary
---------------

This is the first official release of the ``cisco.nae`` collection on 2020-11-25.

Major Changes
-------------

- Add automatic integration test
- Add function getFirstAG() to get an Assurance Group for some API calls
- Add function send_manual_payload() to create pre-change from manual changes
- Add module nae_compliance to manage compliance objects
- Add module nae_delta to manage delta analysis
- Add module nae_file_management to manage NAE file
- Add module nae_offline_analysis to manage NAE offline analysis
- Add requirements in network-integration.requirements.txt

Minor Changes
-------------

- Ability to ignore specific smart events when querying a pre-change analysis
- Add NAE 5.0 & 5.1 compatibility for send_pre_change_payload
- Add check for non_existing AG group for every use of get_assurance_group()
- Add compatibility for NAE 5.1
- Add name in nae_delta's example
- Add parameter in nae_compliance for associating requirement set to AG or not
- Add parameter in nae_compliance to set requirement set status as active/inactive
- Add requests library in import
- Add requirements in network-integration.requirements.txt
- Add test file and corresponding datasets for nae_compliance module
- Add test file for nae_ag module
- Change python version to 3.6
- Remove output data
- Replace self.params[] with self.params.get()
- Update README.md and fix typo for requests_toolbelt in README.md

Bugfixes
--------

- Fix NAE file upload
- Fix all API call endpoints
- Fix crash in deleteAG() when using a non_existing AG
- Fix delay while querying existing PCV analysis
- Fix failing of pre-change analysis when there are only INFO severity events
- Fix idempotency issue for nae_ag module
- Fix idempotency issue for nae_compliance module
- Fix integration test for nae_prechange
- Fix sanity test and typos
- Fix url for Assurance API
- Fix warning of both option name and its alias name are set
- Fix warning of module did not set no_log for apic_password

v0.0.1
======
