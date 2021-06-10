#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import atexit
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
import argparse
import json
import requests
from lxml import etree
from protobix3 import DataContainer
from inf_compare import load_configuration, host_name_startswith_prefix, SITE_V_CENTER, SITE_V_CLOUD


def discover(args):
    conf = load_configuration(args.config, args.gconfig)
    sites_discovery = []
    for site in conf.get('sites'):
        if site['type'] == SITE_V_CENTER or site['type'] == SITE_V_CLOUD:
            sites_discovery.append({'{#SITE_NW_CHECK}': site['name']})
    print(json.dumps({'data': sites_discovery}))


def check_network_adapters(args):
    conf = load_configuration(args.config, args.gconfig)
    errors = []
    for site in conf.get('sites'):
        try:
            result = []
            if site['type'] == SITE_V_CENTER:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                si = SmartConnect(host=site['host'], user=site['user'], pwd=site['password'], sslContext=context)
                atexit.register(Disconnect, si)

                content = si.RetrieveContent()
                container = content.rootFolder
                viewType = [vim.VirtualMachine]
                recursive = True
                containerView = content.viewManager.CreateContainerView(container, viewType, recursive)

                vms = containerView.view
                for vm in vms:
                    vm_name = vm.name.upper()

                    if vm_name in conf['global']['nw_adapter_exclude_hosts']:
                        continue
                    if host_name_startswith_prefix(vm_name, conf['global']['nw_adapter_exclude_prefixes']):
                        continue

                    devices = set()
                    for device in vm.config.hardware.device:
                        if isinstance(device, vim.VirtualEthernetCard) and not isinstance(device, vim.VirtualVmxnet3):
                            devices.add(device.__class__.__name__.split('vim.vm.device.')[-1])
                    if devices:
                        result.append('{0}: {1}'.format(vm_name, ', '.join(devices)))
            elif site['type'] == SITE_V_CLOUD:
                session = requests.session()
                session.verify = False
                session.headers = {'Accept': 'application/*+xml;version=9.0'}
                url = site['url']
                response = session.post(url=url + '/sessions', auth=(site['user'], site['password']), timeout=15)
                session.headers['x-vcloud-authorization'] = response.headers['x-vcloud-authorization']
                page = 1
                while True:
                    # Maximum page size = 128
                    xml = etree.fromstring(
                        session.get(
                            url=url + '/query?type=vm&pageSize=128&page={0}'.format(page)
                        ).text.encode('utf-8')
                    )
                    for vm in xml.findall('.//{*}VMRecord[@isVAppTemplate="false"]'):
                        vm_name = vm.attrib['name'].upper()

                        if vm_name in conf['global']['nw_adapter_exclude_hosts']:
                            continue
                        if host_name_startswith_prefix(vm_name, conf['global']['nw_adapter_exclude_prefixes']):
                            continue

                        vm_info = etree.fromstring(session.get(url=vm.attrib['href']).text.encode('utf-8'))

                        devices = set()
                        # ResourceType="10" is network card
                        for item in vm_info.findall('.//{*}VirtualHardwareSection/{*}Item[{*}ResourceType="10"]'):
                            sub_type_text = item.find('{*}ResourceSubType').text
                            if sub_type_text != 'VMXNET3':
                                devices.add(sub_type_text)
                        if devices:
                            result.append('{0}: {1}'.format(vm_name, ', '.join(devices)))
                    if xml.find('.//{*}Link[@rel="nextPage"]') is None:
                        break
                    page += 1
            if result:
                item = {'site_nw_adapter_check[{0}]'.format(site['name']): '\n'.join(result)}
                # print(item)
                zbx_container = DataContainer()
                zbx_container.server_active = '127.0.0.1'
                zbx_container.server_port = 10051
                zbx_container.data_type = 'items'
                zbx_data = {args.s: item}
                zbx_container.add(zbx_data)
                zbx_container.send()

        except Exception as e:
            errors.append('{0}: {1}'.format(site['name'], e))

    errors_item = {}
    if errors:
        errors_item['site_nw_adapter_check_errors'] = '\n'.join(errors)
    else:
        errors_item['site_nw_adapter_check_errors'] = ''
    # print(errors_item)
    zbx_container = DataContainer()
    zbx_container.server_active = '127.0.0.1'
    zbx_container.server_port = 10051
    zbx_container.data_type = 'items'
    zbx_data = {args.s: errors_item}
    zbx_container.add(zbx_data)
    zbx_container.send()


def main():
    parser = argparse.ArgumentParser(description='Check network adapters')
    parser.add_argument('--gconfig', help='Global configuration file', required=False,
                        default='inf_compare_global.conf')
    parser.add_argument('--config', help='Sites configuration file', required=False,
                        default='inf_compare_cfg.conf')

    subparsers = parser.add_subparsers(help='Check network adapters')

    parser_1 = subparsers.add_parser('check', help='Check')
    parser_1.add_argument('-s', help='Sender host', required=True)
    parser_1.set_defaults(func=check_network_adapters)

    parser_2 = subparsers.add_parser('discover', help='Discover sites')
    parser_2.set_defaults(func=discover)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
