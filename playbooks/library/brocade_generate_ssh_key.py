#!/usr/bin/env python2


DOCUMENTATION = '''
---
module: brocade_generate_ssh_key
short_description: Generate SSH Key on Brocade Switch
description:
    - Generates SSH Key on Brocade Switch
author: Will McLendon
'''

EXAMPLES = '''
# Example Playbook:
---
- name: Brocade ICCX6450 Switch Post Staging
  hosts: icx6450s
  vars:
    username: ansible
    password: password
    logfileDirectory: "/tmp/log"
  connection: local
  gather_facts: no
  tasks:
    - name: Generate SSH Key
      brocade_generate_ssh_key:
         host="{{ inventory_hostname }}"
         username="{{ username }}"
         password="{{ password }}"
         logfileDirectory="{{ logfileDirectory }}"
- name: Brocade ICCX6610 Switch Post Staging
  hosts: icx6610s
  vars:
    username: ansible
    password: password
    logfileDirectory: "/tmp/log"
  connection: local
  gather_facts: no
  tasks:
    - name: Generate SSH Key
      brocade_generate_ssh_key:
         host="{{ inventory_hostname }}"
         username="{{ username }}"
         password="{{ password }}"
         logfileDirectory="{{ logfileDirectory }}"
'''

import logging
from time import sleep

try:
    from pexpect import spawn
    MEETS_IMPORT_REQUIREMENTS = True
except ImportError:
    MEETS_IMPORT_REQUIREMENTS = False


def login(**config):
    hostname = config.get('hostname')
    username = config.get('username')
    password = config.get('password')
    logfile = config.get('logfile')
    brcd_switch = spawn('telnet ' + hostname)
    brcd_switch.logfile = open(logfile, 'w')
    brcd_switch.expect('.*ogin Name:.*')
    brcd_switch.sendline(username)
    brcd_switch.expect('.*assword:.*')
    brcd_switch.sendline(password)
    brcd_switch.expect('.*#.*')
    logging.info('Logged into ' + hostname + ', executing crypto key generate')
    return brcd_switch


def brocade_generate_ssh_key(module):
    hostname = module.params['host']
    logfileDirectory = module.params['logfileDirectory']
    logfile = logfileDirectory + '/' + hostname + '--post-stage-log.log'
    config = dict(hostname=hostname,
                  username=module.params['username'],
                  password=module.params['password'],
                  lofile=logfile)
    results = dict(changed=False, failed=True)

    try:
        # Telnet to device:
        brcd_switch = login(**config)
    except EOF, err:
        msg = "EOF error -- unable to connect to {}".format(module.params['host'])
        results['msg'] = msg
        logging.info('EOF Error on {}'.format(module.params['host']))
        logging.info(err)
        module.fail_json(msg='ERROR -- Unable to connect to {}'.format(module.params['host']))
    except TIMEOUT, err:
        msg = "TIMEOUT error -- did not get expected values returned on {}".format(module.params['host'])
        results['msg'] = msg
        logging.info('TIMEOUT Error on {}'.format(module.params['host']))
        logging.info(err)
        module.fail_json(msg='ERROR - Did not get expected values returned on {}'.format(module.params['host']))
    else:
        # we are now logged in, can run a command now
        # Enter config mode and generate crypto key, then exit config mode:
        brcd_switch.sendline('config t')
        brcd_switch.expect('.*\(config\).*')
        brcd_switch.sendline('crypto key zeroize')
        brcd_switch.expect('.*\(config\).*')
        brcd_switch.sendline('crypto key generate')
        brcd_switch.expect('(.*Key pair is successfully create.*)|(.*ey already exist.*)')
        brcd_switch.expect('.*(config).*')
        brcd_switch.sendline('end')
        brcd_switch.expect('.*#.*')
        sleep(5)
        logging.info('Crypto key generated, now copying over bootrom...')
        brcd_switch.sendline('logout')
        sleep(5)

        # if we get here, all work completed successfully, mark as Changed
        results['changed'] = True
        results['failed'] = False
        return results
    finally:
        brcd_switch.close()


def main():
    module = AnsibleModule(
        argument_spec=dict(host=dict(required=True),
                           username=dict(required=True),
                           password=dict(required=True),
                           logfileDirectory=dict(required=True)))

    if not MEETS_IMPORT_REQUIREMENTS:
        module.fail_json(msg='pexpect is required for this module.')
        return

    logging.info("Connecting to switch: {}".format(module.params['host']))
    results = brocade_generate_ssh_key(module)

    module.exit_json(**results)

from ansible.module_utils.basic import *
main()
