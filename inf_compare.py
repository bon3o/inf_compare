#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import requests
import json
import ssl
import atexit
import redis
from decimal import Decimal
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
from configobj import ConfigObj
from lxml import etree
import hmac
import hashlib
import base64
import time
from urllib.parse import quote_plus
from protobix3 import DataContainer


REDIS_DB = 3

insight_params = [
    ('objectSchemaId', 2),
    ('resultPerPage', 10000)
]

OS = {
    'WINDOWS': 'Windows',
    'LINUX': 'Linux',
    'CENTOS': 'Linux',
    'FREEPBX': 'Linux'
}

INSIGHT_REQUIRED_TYPE_ATTR = 'VM'

ROUND_DIGITS = 1
GB_IN_MB = Decimal(1024)
GB_IN_BYTES = Decimal(1024 ** 3)

OBJECT_TYPE_ATTRIBUTE_ID_OS = 221
OBJECT_TYPE_ATTRIBUTE_ID_STATUS = 226
OBJECT_TYPE_ATTRIBUTE_ID_TENANT = 232
OBJECT_TYPE_ATTRIBUTE_ID_CPU_CORES = 1473
OBJECT_TYPE_ATTRIBUTE_ID_MEMORY_RAM = 1474
OBJECT_TYPE_ATTRIBUTE_ID_OS_DISK = 1475
OBJECT_TYPE_ATTRIBUTE_ID_DATA_DISK = 1477
OBJECT_TYPE_ATTRIBUTE_ID_PARENT = 624
OBJECT_TYPE_ATTRIBUTE_ID_TYPE = 256
OBJECT_TYPE_ATTRIBUTE_ID_ENV = 249
OBJECT_TYPE_ATTRIBUTE_ID_ENV_SEC = 1432


INSIGHT_OS_EXCLUDE = ['Linux Appliance']

CARD_ATTR_OS = 'OS'
CARD_ATTR_STATUS = 'Status'
CARD_ATTR_TENANT = 'Tenant'
CARD_ATTR_CPU_CORES = 'CPU cores'
CARD_ATTR_MEMORY_RAM = 'Memory RAM'
CARD_ATTR_OS_DISC = 'OS disk'
CARD_ATTR_DATA_DISK = 'Data hdd'
CARD_ATTR_PARENT = 'Parent'
CARD_ATTR_TYPE = 'Type'
CARD_ATTR_ENV = 'Env'

PROD_ENV = 'PROD'
TEST_ENV = 'TEST'

# Site types
SITE_INTEROUTE = 0
SITE_V_CENTER = 1
SITE_V_CLOUD = 2
SITE_ZABBIX = 3
SITE_INSIGHT = 4


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)


def get_value_not_none(value, error):
    if value is not None:
        return value
    raise Exception(error)


def get_as_set(value):
    if isinstance(value, list):
        return set(value)
    else:
        return set([value])


def get_as_set_uc(value):
    if isinstance(value, list):
        return set([v.upper() for v in value])
    else:
        return set([value.upper()])


def load_configuration(cfg_file_name, g_cfg_file_name):
    config = ConfigObj(cfg_file_name)
    g_config = ConfigObj(g_cfg_file_name)

    sites = []

    # Load Interoute sites configuration
    interoute_cfg = config.get('INTEROUTE', {})
    if interoute_cfg:
        for interoute in interoute_cfg.sections:
            sites.append({
                'name': interoute,
                'url': interoute_cfg[interoute].get('URL', interoute_cfg['URL']),
                'secret': get_value_not_none(
                    interoute_cfg[interoute].get('SECRET', interoute_cfg.get('SECRET')),
                    'SECRET is not defined for {0}'.format(interoute)
                ),
                'key': get_value_not_none(
                    interoute_cfg[interoute].get('KEY', interoute_cfg.get('KEY')),
                    'KEY is not defined for {0}'.format(interoute)
                ),
                'tenant': get_value_not_none(
                    interoute_cfg[interoute].get('TENANT', interoute_cfg.get('TENANT')),
                    'TENANT is not defined for {0}'.format(interoute)
                ),
                'regions': get_value_not_none(
                    interoute_cfg[interoute].get('REGIONS', interoute_cfg.get('REGIONS')),
                    'REGIONS is not defined for {0}'.format(interoute)
                ),
                'type': SITE_INTEROUTE
            })

    # Load vCenter sites configuration
    v_center_cfg = config.get('VCENTER', {})
    if v_center_cfg:
        for v_center in v_center_cfg.sections:
            sites.append({
                'name': v_center,
                'host': v_center_cfg[v_center]['HOST'],
                'user': get_value_not_none(
                    v_center_cfg[v_center].get('USER', v_center_cfg.get('USER')),
                    'USER is not defined for {0}'.format(v_center)
                ),
                'password': get_value_not_none(
                    v_center_cfg[v_center].get('PASSWORD', v_center_cfg.get('PASSWORD')),
                    'PASSWORD is not defined for {0}'.format(v_center)
                ),
                'type': SITE_V_CENTER
            })

    # Load vCloud sites configuration
    v_cloud_cfg = config.get('VCLOUD', {})
    if v_cloud_cfg:
        for v_cloud in v_cloud_cfg.sections:
            sites.append({
                'name': v_cloud,
                'url': v_cloud_cfg[v_cloud]['URL'],
                'user': get_value_not_none(
                    v_cloud_cfg[v_cloud].get('USER', v_cloud_cfg.get('USER')),
                    'USER is not defined for {0}'.format(v_cloud)
                ),
                'password': get_value_not_none(
                    v_cloud_cfg[v_cloud].get('PASSWORD', v_cloud_cfg.get('PASSWORD')),
                    'PASSWORD is not defined for {0}'.format(v_cloud)
                ),
                'tenant': get_value_not_none(
                    v_cloud_cfg[v_cloud].get('TENANT', v_cloud_cfg.get('TENANT')),
                    'TENANT is not defined for {0}'.format(v_cloud)
                ),
                'type': SITE_V_CLOUD
            })

    zabbix_cfg = config.get('ZABBIX', {})
    if zabbix_cfg:
        sites.append({
            'name': 'zabbix',
            'user': zabbix_cfg.get('USER'),
            'password': zabbix_cfg.get('PASSWORD'),
            'url': zabbix_cfg.get('URL'),
            'base_templates': zabbix_cfg.get('BASETEMPLATES'),
            'type': SITE_ZABBIX
        })

    insight_cfg = config.get('INSIGHT', {})
    if insight_cfg:
        sites.append({
            'name': 'insight',
            'user': insight_cfg.get('USER'),
            'password': insight_cfg.get('PASSWORD'),
            'url': insight_cfg.get('URL'),
            'sites_iql': insight_cfg.get('SITES_IQL'),
            'type': SITE_INSIGHT
        })

    global_cfg = g_config.get('GLOBAL', {})
    # Redefined OS disk names
    os_disk_cfg = g_config.get('OS_DISK', {})
    os_disk = {}
    for host in os_disk_cfg:
        os_disk[host.upper()] = os_disk_cfg[host]

    return {
        'sites': sites,
        'global': {
            'exclude_hosts': [host.upper() for host in global_cfg.get('EXCLUDE_HOSTS', [])],
            'exclude_prefixes': [prefix.upper() for prefix in global_cfg.get('EXCLUDE_PREFIXES', [])],
            # Do not check adapters for this hosts
            'nw_adapter_exclude_hosts': [host.upper() for host in global_cfg.get('NW_ADAPTER_EXCLUDE_HOSTS', [])],
            'nw_adapter_exclude_prefixes': [
                prefix.upper() for prefix in global_cfg.get('NW_ADAPTER_EXCLUDE_PREFIXES', [])
            ],
            'redis': global_cfg.get('REDIS'),
            'redis_ttl': int(global_cfg.get('REDIS_TTL', 600)),
            'checks_count': int(global_cfg.get('CHECKS_COUNT', 4)),

            'prod_templates_win': get_as_set(global_cfg.get('PROD_TEMPLATES_WIN', [])),
            'prod_templates_lin': get_as_set(global_cfg.get('PROD_TEMPLATES_LIN', [])),
            'test_templates_win': get_as_set(global_cfg.get('TEST_TEMPLATES_WIN', [])),
            'test_templates_lin': get_as_set(global_cfg.get('TEST_TEMPLATES_LIN', [])),
            'wt_templates_prod_lin': get_as_set(global_cfg.get('WT_TEMPLATES_PROD_LIN', [])),
            'wt_templates_test_lin': get_as_set(global_cfg.get('WT_TEMPLATES_TEST_LIN', [])),
            'templates_check_exclude_hosts': get_as_set_uc(global_cfg.get('TEMPLATES_CHECK_EXCLUDE_HOSTS', [])),
            'wt_env': get_as_set(global_cfg.get('WT_ENV', []))
        },
        'os_disk': os_disk
    }


def get_os_type(os):
    """
    :param os: value of os attribute
    :return: OS type (value of OS dict) from OS or os as is if os doesn't contain one of OS dict keys
    If os in INSIGHT_OS_EXCLUDE return os type as is
    """
    if os in INSIGHT_OS_EXCLUDE:
        return os

    for key in OS:
        if key in os.upper():
            return OS[key]
    return os


def host_name_startswith_prefix(host_name, excluded_prefixes):
    for prefix in excluded_prefixes:
        if host_name.startswith(prefix):
            return True
    return False


class ZabbixAPI(object):
    def __init__(self, user, password, url, base_templates):
        self.zbx_req_json = {'jsonrpc': '2.0'}
        self.url = url
        self.id = 1
        auth_token = self.call(method='user.login', params={'user': user, 'password': password})
        self.zbx_req_json['auth'] = auth_token
        self.base_templates = [base_template.upper() for base_template in base_templates]

    def call(self, method, params):
        self.zbx_req_json['method'] = method
        self.zbx_req_json['params'] = params
        self.zbx_req_json['id'] = self.id
        req_result = requests.post(self.url, json=self.zbx_req_json)
        self.id += 1
        if 'error' in req_result.json():
            raise Exception('call api: {0}'.format(req_result.json()['error']['data']))
        else:
            return req_result.json()['result']

    def get_host_cards(self):
        cards = {}
        host_get_params = {
            'output': [
                'name'
            ],
            'filter': {
                'status': '0'
            },
            'selectParentTemplates': ['name'],
            'selectGroups': ['name']
        }
        for host in self.call(method='host.get', params=host_get_params):
            host_templates = []
            for template in host['parentTemplates']:
                if template['name'].upper() in self.base_templates:
                    host_templates.append(template['name'])
            if host_templates:
                cards[host['name'].partition('.')[0].upper()] = {
                    'templates': host_templates,
                    'groups': [group['name'] for group in host['groups']]
                }
        return cards


class VCenterAPI(object):
    DEFAULT_OS_DISK_LABEL = 'Hard disk 1'

    def __init__(self, host, user, password, os_disk_remap, excluded_hosts, excluded_prefixes):
        """
        :param host: vCenter host
        :param user: vCenter API user
        :param password: vCenter API password
        :param os_disk_remap: dict of 'host':'OS Disk name' if first disk is not system
        """
        self.os_disk_remap = os_disk_remap
        self.excluded_hosts = excluded_hosts
        self.excluded_prefixes = excluded_prefixes
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.si = SmartConnect(host=host, user=user, pwd=password, sslContext=context)
        atexit.register(Disconnect, self.si)
        self.vcentererrors = []

    def __fill_host_cards(self, children, cluster, cards):
        """
        HostSystem - ESXi
        ComputeResource - Cluster
        :param children: current node (Datacenter, ComputeResource, HostSystem, VirtualMachine)
        :param cluster: current Cluster name
        :param cards: current dict with hosts cards
        :return: result dict with hosts cards (card is dict with host attributes such as OS, RAM, etc)
        """
        for child in children:
            if isinstance(child, vim.Datacenter):
                # child.name is DC
                self.__fill_host_cards(child.hostFolder.childEntity, '', cards)
            elif isinstance(child, vim.ComputeResource):
                # child.name is Cluster
                self.__fill_host_cards(child.host, child.name, cards)
            elif isinstance(child, vim.HostSystem):
                # child.name is ESXi
                self.__fill_host_cards(child.vm, cluster, cards)
            elif isinstance(child, vim.VirtualMachine):
                # child.name is VM
                vm_name = child.name.upper()
                if child.config.template:
                    continue
                if vm_name in self.excluded_hosts:
                    continue
                if host_name_startswith_prefix(vm_name, self.excluded_prefixes):
                    continue

                os_disk_label = self.os_disk_remap.get(vm_name, VCenterAPI.DEFAULT_OS_DISK_LABEL)

                os_disk_size_bytes = 0
                data_disk_size_bytes = 0
                for dev in child.config.hardware.device:
                    if isinstance(dev, vim.vm.device.VirtualDisk):
                        if dev.deviceInfo.label != os_disk_label:
                            data_disk_size_bytes += dev.capacityInBytes
                        else:
                            os_disk_size_bytes = dev.capacityInBytes
                """
                Added try block to see if vcenter gives values of type None
                for some reason. 
                """
                try:
                    cardAttrMemoryRam = round(child.summary.config.memorySizeMB / GB_IN_MB, ROUND_DIGITS)
                    cardAttrOsDisc = round(os_disk_size_bytes / GB_IN_BYTES, ROUND_DIGITS)
                    cardAttrDataDisk = round(data_disk_size_bytes / GB_IN_BYTES, ROUND_DIGITS)
                except Exception as e:
                    self.vcentererrors.append("Error getting info for host {0} from vCenter. ram size: {1}, os disk: {2}, data disk: {3}. Error: {4}".format(vm_name, cardAttrMemoryRam, cardAttrOsDisc, cardAttrDataDisk, e))
                    continue
                cards[vm_name] = {
                    CARD_ATTR_PARENT: cluster,
                    CARD_ATTR_OS: get_os_type(child.summary.config.guestFullName),
                    CARD_ATTR_CPU_CORES: child.summary.config.numCpu,
                    CARD_ATTR_MEMORY_RAM: cardAttrMemoryRam,
                    CARD_ATTR_OS_DISC: cardAttrOsDisc,
                    CARD_ATTR_DATA_DISK: cardAttrDataDisk
                }

    def get_host_cards(self):
        content = self.si.RetrieveContent()
        children = content.rootFolder.childEntity
        cards = {}
        self.__fill_host_cards(children=children, cluster=None, cards=cards)
        return cards


class InsightAPI(object):
    def __init__(self, params, excluded_hosts, excluded_prefixes, user, password, url, iql):
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.base_url = url + '/rest/insight/1.0/iql/objects'
        self.params = params.copy()
        self.params.append(('iql', iql))
        self.excluded_hosts = excluded_hosts
        self.excluded_prefixes = excluded_prefixes

    def get_environments(self):
        params = [
            ('objectSchemaId', 2),
            ('resultPerPage', 10000),
            ('iql', 'objectType IN objectTypeAndChildren("Environment") '
                    'AND "Type" IS NOT EMPTY AND "Status" != "Архив"')
        ]
        environments_attrs = self.session.get(url=self.base_url, params=params).json()
        type_code = [
            insight_attr['position'] for insight_attr in environments_attrs['objectTypeAttributes']
            if insight_attr['name'] == 'Type'
        ]

        if len(type_code) != 1:
            raise Exception('Error in query')
        else:
            attr_pos = type_code[0]
        environments = {}
        for entry in environments_attrs['objectEntries']:
            environments[entry['objectKey']] = {
                'name': entry['name'],
                'type': entry['attributes'][attr_pos]['objectAttributeValues'][0]['displayValue'].upper()
            }
        return environments

    def get_host_cards(self):
        environments = self.get_environments()
        entries = self.session.get(url=self.base_url, params=self.params).json()

        insight_hosts = {}
        for entry in entries.get('objectEntries', []):
            try:
                host_name = entry['name'].upper()
                if host_name in self.excluded_hosts:
                    continue
                if host_name_startswith_prefix(host_name, self.excluded_prefixes):
                    continue
                insight_hosts[host_name] = self.__fill_host_cards(
                    attributes=entry['attributes'],
                    environments=environments
                )
            except Exception as e:
                print('Host {0} {1}'.format(entry['name'], e))
        return insight_hosts

    @staticmethod
    def __fill_host_cards(attributes, environments):
        """
        :param attributes: JSON with host attributes
        :return: host card filled with certain attribute values
        """
        card = {
            CARD_ATTR_PARENT: 'None',
            CARD_ATTR_OS: 'None',
            CARD_ATTR_CPU_CORES: 0,
            CARD_ATTR_MEMORY_RAM: Decimal('0'),
            CARD_ATTR_OS_DISC: Decimal('0'),
            CARD_ATTR_DATA_DISK: Decimal('0'),
            CARD_ATTR_TYPE: 'None',
            CARD_ATTR_TENANT: 'None',
            CARD_ATTR_ENV: 'None'
        }

        cur_env = set()

        for attribute in attributes:
            if not attribute['objectAttributeValues']:
                continue

            attr_id = attribute['objectTypeAttributeId']
            # noinspection PyBroadException
            try:
                if attr_id == OBJECT_TYPE_ATTRIBUTE_ID_OS:
                    card[CARD_ATTR_OS] = get_os_type(attribute['objectAttributeValues'][0]['displayValue'])
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_STATUS:
                    card[CARD_ATTR_STATUS] = attribute['objectAttributeValues'][0]['displayValue']
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_TENANT:
                    card[CARD_ATTR_TENANT] = attribute['objectAttributeValues'][0]['displayValue']
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_CPU_CORES:
                    card[CARD_ATTR_CPU_CORES] = int(attribute['objectAttributeValues'][0]['displayValue'])
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_MEMORY_RAM:
                    card[CARD_ATTR_MEMORY_RAM] = Decimal(attribute['objectAttributeValues'][0]['displayValue'])
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_OS_DISK:
                    card[CARD_ATTR_OS_DISC] = Decimal(attribute['objectAttributeValues'][0]['displayValue'])
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_DATA_DISK:
                    card[CARD_ATTR_DATA_DISK] = Decimal(attribute['objectAttributeValues'][0]['displayValue'])
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_PARENT:
                    card[CARD_ATTR_PARENT] = attribute['objectAttributeValues'][0]['displayValue']
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_TYPE:
                    card[CARD_ATTR_TYPE] = attribute['objectAttributeValues'][0]['displayValue']
                elif attr_id == OBJECT_TYPE_ATTRIBUTE_ID_ENV or attr_id == OBJECT_TYPE_ATTRIBUTE_ID_ENV_SEC:
                    for env_attr in attribute['objectAttributeValues']:
                        cur_env.add(env_attr['referencedObject']['objectKey'])
            except Exception as e:
                pass
                # raise Exception('bad Insight value in attribute with id {0} error {1}'.format(attr_id, e))
        card[CARD_ATTR_ENV] = [environments[env] for env in cur_env if env in environments]
        return card


class VCloudAPI(object):
    DEFAULT_OS_DISK_LABEL = 'Hard disk 1'

    def __init__(self, url, user, password, os_disk_remap, excluded_hosts, excluded_prefixes):
        self.session = requests.session()
        self.session.verify = False
        self.session.headers = {'Accept': 'application/*+xml;version=30.0'}
        self.url = url
        response = self.session.post(url=self.url + '/sessions', auth=(user, password), timeout=15)
        self.session.headers['x-vcloud-authorization'] = response.headers['x-vcloud-authorization']
        self.os_disk_remap = os_disk_remap
        self.excluded_hosts = excluded_hosts
        self.excluded_prefixes = excluded_prefixes
        # print(response.text)
        # print(response.headers)

    def get_host_cards(self):
        page = 1
        cards = {}
        while True:
            # Maximum page size = 128
            xml = etree.fromstring(
                self.session.get(
                    url=self.url + '/query?type=vm&pageSize=128&page={0}'.format(page)
                ).text.encode('utf-8')
            )
            for vm in xml.findall('.//{*}VMRecord[@isVAppTemplate="false"]'):
                vm_name = vm.attrib['name'].upper()
                if vm_name in self.excluded_hosts:
                    continue
                if host_name_startswith_prefix(vm_name, self.excluded_prefixes):
                    continue
                card = {
                    CARD_ATTR_OS: get_os_type(vm.attrib['guestOs']),
                    CARD_ATTR_CPU_CORES: int(vm.attrib['numberOfCpus']),
                    CARD_ATTR_MEMORY_RAM: round(Decimal(vm.attrib['memoryMB']) / GB_IN_MB, ROUND_DIGITS),
                }
                os_disk_label = self.os_disk_remap.get(vm_name, VCloudAPI.DEFAULT_OS_DISK_LABEL)

                vm_info = etree.fromstring(self.session.get(url=vm.attrib['href']).text.encode('utf-8'))
                data_disk_size_bytes = Decimal('0')
                os_disk_size_bytes = Decimal('0')
                for item in vm_info.findall('.//{*}VirtualHardwareSection/{*}Item[{*}Description="Hard disk"]'):
                    if item.find('{*}ElementName').text == os_disk_label:
                        os_disk_size_bytes = Decimal(item.find('{*}VirtualQuantity').text)
                    else:
                        data_disk_size_bytes += Decimal(item.find('{*}VirtualQuantity').text)
                card[CARD_ATTR_OS_DISC] = round(os_disk_size_bytes / GB_IN_BYTES, ROUND_DIGITS)
                card[CARD_ATTR_DATA_DISK] = round(data_disk_size_bytes / GB_IN_BYTES, ROUND_DIGITS)
                cards[vm_name] = card
            if xml.find('.//{*}Link[@rel="nextPage"]') is None:
                break
            page += 1
        return cards


class InterouteAPI(object):
    """
    API Description:
    https://cloudstore.interoute.com/knowledge-centre/library/vdc-api-introduction-api
    """
    def __init__(self, url, api_key, api_secret, regions, os_disk_remap, excluded_hosts, excluded_prefixes):
        self.url = url
        self.api_key = api_key
        self.api_secret = api_secret
        self.regions = regions
        self.os_disk_remap = os_disk_remap
        self.excluded_hosts = excluded_hosts
        self.excluded_prefixes = excluded_prefixes

    def __request_api(self, cmd, params):
        api_params = {
            'command': cmd,
            'apiKey': self.api_key,
            'response': 'json'
        }
        api_params.update(params)
        sorted_keys = sorted(api_params, key=str.lower)

        req = '&'.join([key+'='+quote_plus(api_params[key]) for key in sorted_keys])
        hash_cmd = '&'.join([key+'='+quote_plus(api_params[key]).replace('+', '%20') for key in sorted_keys]).lower()

        sig = quote_plus(base64.b64encode(hmac.new(self.api_secret.encode(), hash_cmd.encode(), hashlib.sha1).digest()))

        req += '&signature=%s' % sig
        return requests.get(url=self.url+'?'+req).json()

    def get_host_cards(self):
        cards = {}
        errors = []
        for region in self.regions:
            region_param = {'region': region}
            hosts = self.__request_api(cmd='listVirtualMachines', params=region_param)
            volumes = self.__request_api(cmd='listVolumes', params=region_param)

            host_id_volumes = {}
            for volume in volumes.get('listvolumesresponse', {}).get('volume', []):
                host_id = volume.get('virtualmachineid', '')
                volume_type = volume['type']
                if host_id:
                    if volume_type == 'ROOT':
                        host_id_volumes.setdefault(host_id, {})[CARD_ATTR_OS_DISC] = Decimal(volume['size'])
                    elif volume_type == 'DATADISK':
                        host_id_volumes.setdefault(host_id, {}).setdefault(CARD_ATTR_DATA_DISK, Decimal(0))
                        host_id_volumes[host_id][CARD_ATTR_DATA_DISK] += Decimal(volume['size'])
                    else:
                        print('Unknown disk type: {0}'.format(volume['type']))

            os_types = self.__request_api(cmd='listOsTypes', params=region_param)
            os_id_types = {}
            for os in os_types.get('listostypesresponse', {}).get('ostype', []):
                os_id_types[os['id']] = os['description']

            for host in hosts.get('listvirtualmachinesresponse', {}).get('virtualmachine', []):
                host_name = host['name'].upper()
                display_name = host['displayname'].upper()
                host_id = host['id']
                # If name != displayname then issue
                # Insight contains name
                if host_name != display_name:
                    errors.append('name != displayname : {0}, {1}'.format(host['name'], host['displayname']))
                if host_name in self.excluded_hosts:
                    continue
                if host_name_startswith_prefix(host_name, self.excluded_prefixes):
                    continue

                cards[host_name] = {
                    CARD_ATTR_OS_DISC: round(host_id_volumes.get(host_id, {}).get(
                        CARD_ATTR_OS_DISC, Decimal(0)) / GB_IN_BYTES, ROUND_DIGITS),
                    CARD_ATTR_DATA_DISK: round(host_id_volumes.get(host_id, {}).get(
                        CARD_ATTR_DATA_DISK, Decimal(0)) / GB_IN_BYTES, ROUND_DIGITS),
                    CARD_ATTR_CPU_CORES: int(host['cpunumber']),
                    CARD_ATTR_MEMORY_RAM: round(Decimal(host['memory']) / GB_IN_MB, ROUND_DIGITS),
                    CARD_ATTR_OS: get_os_type(os_id_types.get(host['guestosid'], ''))
                }

        return cards, errors


def discover(args):
    redis_client = redis.Redis(host=args.redis, port=6379, db=REDIS_DB)
    keys = redis_client.keys('*')
    sites = []
    for b_key in keys:
        key = b_key.decode()
        if key not in ['insight', 'zabbix', 'host_seen_counter']:
            sites.append(
                {
                    '{#SITE}': key.upper()
                }
            )
    return json.dumps({'data': sites}, indent=4)


def collect(args):
    conf = load_configuration(args.config, args.gconfig)
    redis_client = redis.Redis(host=conf['global']['redis'], port=6379, db=REDIS_DB)
    collected_sites_names = []
    collect_errors = []
    for site in conf.get('sites'):
        try:
            if site['type'] == SITE_V_CENTER:
                v_center = VCenterAPI(host=site['host'],
                                      user=site['user'],
                                      password=site['password'],
                                      os_disk_remap=conf['os_disk'],
                                      excluded_hosts=conf['global']['exclude_hosts'],
                                      excluded_prefixes=conf['global']['exclude_prefixes'])

                v_center_hosts = v_center.get_host_cards()
                redis_client.set(
                    site['name'],
                    json.dumps(
                        {
                            'hosts': v_center_hosts,
                            'ts': time.time(),
                            'type': SITE_V_CENTER
                        },
                        cls=DecimalEncoder
                    ),
                    ex=conf['global']['redis_ttl']
                )
                collected_sites_names.append(site['name'])
                if v_center.vcentererrors:
                    collect_errors.append(';'.join(v_center.vcentererrors))
            elif site['type'] == SITE_V_CLOUD:
                v_cloud = VCloudAPI(url=site['url'],
                                    user=site['user'],
                                    password=site['password'],
                                    os_disk_remap=conf['os_disk'],
                                    excluded_hosts=conf['global']['exclude_hosts'],
                                    excluded_prefixes=conf['global']['exclude_prefixes'])
                v_cloud_hosts = v_cloud.get_host_cards()
                redis_client.set(
                    site['name'],
                    json.dumps(
                        {
                            'hosts': v_cloud_hosts,
                            'ts': time.time(),
                            'tenant': site['tenant'],
                            'type': SITE_V_CLOUD
                        },
                        cls=DecimalEncoder
                    ),
                    ex=conf['global']['redis_ttl']
                )
                collected_sites_names.append(site['name'])
            elif site['type'] == SITE_INTEROUTE:
                interoute = InterouteAPI(url=site['url'],
                                         api_key=site['key'],
                                         api_secret=site['secret'],
                                         regions=site['regions'],
                                         os_disk_remap=conf['os_disk'],
                                         excluded_hosts=conf['global']['exclude_hosts'],
                                         excluded_prefixes=conf['global']['exclude_prefixes'])
                interoute_hosts, errors = interoute.get_host_cards()
                for error in errors:
                    collect_errors.append('{0}, {1}'.format(site['name'], error))
                redis_client.set(
                    site['name'],
                    json.dumps(
                        {
                            'hosts': interoute_hosts,
                            'ts': time.time(),
                            'tenant': site['tenant'],
                            'type': SITE_INTEROUTE
                        },
                        cls=DecimalEncoder
                    ),
                    ex=conf['global']['redis_ttl']
                )
                collected_sites_names.append(site['name'])
            elif site['type'] == SITE_ZABBIX:
                zabbix = ZabbixAPI(url=site['url'],
                                   user=site['user'],
                                   password=site['password'],
                                   base_templates=site['base_templates'])
                zabbix_hosts = zabbix.get_host_cards()
                redis_client.set(
                    site['name'],
                    json.dumps(
                        {
                            'hosts': zabbix_hosts,
                            'ts': time.time(),
                            'type': SITE_ZABBIX
                        },
                        cls=DecimalEncoder
                    ),
                    ex=conf['global']['redis_ttl']
                )
                collected_sites_names.append(site['name'])
            elif site['type'] == SITE_INSIGHT:
                insight = InsightAPI(user=site['user'],
                                     password=site['password'],
                                     url=site['url'],
                                     excluded_hosts=conf['global']['exclude_hosts'],
                                     excluded_prefixes=conf['global']['exclude_prefixes'],
                                     params=insight_params,
                                     iql=site['sites_iql'])
                insight_hosts_sites = insight.get_host_cards()
                redis_client.set(
                    site['name'],
                    json.dumps(
                        {
                            'hosts_sites': insight_hosts_sites,
                            'ts': time.time(),
                            'type': SITE_INSIGHT
                        },
                        cls=DecimalEncoder
                    ),
                    ex=conf['global']['redis_ttl']
                )
                collected_sites_names.append(site['name'])
        except Exception as e:
            collect_errors.append('{0}: {1}'.format(site['name'], e))

    zbx_container = DataContainer()
    zbx_container.server_active = '127.0.0.1'
    zbx_container.server_port = 10051
    zbx_container.data_type = 'items'
    zbx_data = {
        args.s: {
            'collected_sites': '\n'.join(collected_sites_names),
            'collect_errors': '\n'.join(collect_errors)
        }
    }
    zbx_container.add(zbx_data)
    zbx_container.send()


def compare(args):
    conf = load_configuration(None, args.gconfig)
    redis_client = redis.Redis(host=conf['global']['redis'], port=6379, db=REDIS_DB)

    host_seen_counter_val = redis_client.get('host_seen_counter')
    host_seen_counter = {}
    hosts_current = set()
    if host_seen_counter_val is not None:
        host_seen_counter = json.loads(host_seen_counter_val.decode())
        hosts_current = set(host_seen_counter.keys())
    hosts_to_remove = hosts_current.copy()

    insight_hosts_value = redis_client.get('insight')
    if not insight_hosts_value:
        return 'Insight data not found'
    else:
        insight_hosts_value = insight_hosts_value.decode()

    zabbix_hosts_value = redis_client.get('zabbix')
    if not zabbix_hosts_value:
        return 'Zabbix data not found'
    else:
        zabbix_hosts_value = zabbix_hosts_value.decode()

    insight_values = json.loads(insight_hosts_value)
    insight_hosts = insight_values.get('hosts_sites', {})

    zabbix_values = json.loads(zabbix_hosts_value)
    zabbix_hosts = zabbix_values.get('hosts', {})

    insight_host_names = set(insight_hosts.keys())
    zabbix_host_names = set(zabbix_hosts.keys())

    insight_zabbix_intersect = zabbix_host_names.intersection(insight_host_names)

    hosts_to_add = insight_host_names.difference(hosts_current)
    hosts_to_remove -= insight_host_names

    keys = redis_client.keys('*')

    items = {}

    cur_ts = time.time()
    items['insight_data_age'] = round((cur_ts - float(insight_values['ts'])) / 60)
    items['zabbix_data_age'] = round((cur_ts - float(zabbix_values['ts'])) / 60)

    for b_key in keys:
        key = b_key.decode()
        if key not in ['insight', 'zabbix', 'host_seen_counter']:
            differences_insight = []
            differences_zabbix = []

            site_hosts = json.loads(redis_client.get(b_key).decode())

            # Get hosts that exist in vCloud but not in Insight
            site_host_names = set(site_hosts['hosts'].keys())

            hosts_to_add.update(site_host_names.difference(hosts_current))
            hosts_to_remove -= site_host_names

            items['data_age[{0}]'.format(key.upper())] = round((cur_ts - float(site_hosts['ts'])) / 60)

            site_insight_diff = site_host_names.difference(insight_host_names)
            site_zabbix_diff = site_host_names.difference(zabbix_host_names)

            for host in site_insight_diff:
                if host_seen_counter.get(host, 0) + 1 < conf['global']['checks_count']:
                    continue
                differences_insight.append('Host present,{0},Present,Not present'.format(host))
            for host in site_zabbix_diff:
                if host_seen_counter.get(host, 0) + 1 < conf['global']['checks_count']:
                    continue
                if insight_hosts.get(host, {}).get(CARD_ATTR_STATUS, '') != 'Выключен':
                    differences_zabbix.append('Host present,{0},Present,Not present'.format(host))

            # Compare attributes for host intersection
            site_insight_intersection = site_host_names.intersection(insight_host_names)
            for host in site_insight_intersection:
                site_host_attr = site_hosts['hosts'][host]
                insight_host_attr = insight_hosts[host]
                if site_hosts['type'] == SITE_V_CENTER:
                    pass
                # Check TENANT in Insight for Interoute & vCloud
                elif site_hosts['type'] in [SITE_V_CLOUD, SITE_INTEROUTE]:
                    if insight_host_attr[CARD_ATTR_TENANT] != site_hosts['tenant']:
                        differences_insight.append('Tenant,{0},{1},{2}'.format(
                            host,
                            site_hosts['tenant'],
                            insight_host_attr[CARD_ATTR_TENANT]
                        ))
                #  Compare defined site (vCenter, vCloud, Interoute) attributes with Insight
                for attr in site_host_attr:
                    # Do not compare OS if Insight OS in INSIGHT_OS_EXCLUDE
                    if attr == CARD_ATTR_OS and insight_host_attr[attr] in INSIGHT_OS_EXCLUDE:
                        continue
                    if site_host_attr[attr] != insight_host_attr[attr]:
                        differences_insight.append('{0},{1},{2},{3}'.format(
                            attr,
                            host,
                            site_host_attr[attr],
                            insight_host_attr[attr]
                        ))
                # Insight attribute TYPE must be equal INSIGHT_REQUIRED_TYPE_ATTR
                if insight_host_attr[CARD_ATTR_TYPE] != INSIGHT_REQUIRED_TYPE_ATTR:
                    differences_insight.append('Type,{0},{1},{2}'.format(
                            host,
                            INSIGHT_REQUIRED_TYPE_ATTR,
                            insight_host_attr[CARD_ATTR_TYPE]
                    ))

            if differences_insight:
                differences_insight.insert(0, 'Error,Host,Fact Value,Insight Value')
                items['insight[{0}]'.format(key.upper())] = '\n'.join(differences_insight)
            else:
                items['insight[{0}]'.format(key.upper())] = ''

            if differences_zabbix:
                differences_zabbix.insert(0, 'Error,Host,Fact Value,Zabbix Value')
                items['zabbix[{0}]'.format(key.upper())] = '\n'.join(differences_zabbix)
            else:
                items['zabbix[{0}]'.format(key.upper())] = ''

            insight_host_names = insight_host_names - site_host_names

    # Also remove HW hosts from insight_host_names (rest hosts)
    hw_hosts = set()
    hw_hosts_not_in_zabbix = []
    for host in insight_host_names:
        if insight_hosts[host][CARD_ATTR_TYPE] == 'HW':
            hw_hosts.add(host)
            if host_seen_counter.get(host, 0) + 1 >= conf['global']['checks_count'] and host not in zabbix_host_names:
                hw_hosts_not_in_zabbix.append('Host {0} is not in Zabbix or is not linked to a base template'.format(host))

    if hw_hosts_not_in_zabbix:
        items['hw_hosts_not_in_zabbix'] = '\n'.join(hw_hosts_not_in_zabbix)
    else:
        items['hw_hosts_not_in_zabbix'] = ''

    insight_host_names = insight_host_names - hw_hosts

    if insight_host_names:
        insight_rest_hosts = ['Error,Host,Fact Value,Insight Value']
        for host in insight_host_names:
            insight_rest_hosts.append('Host present,{0},Not present,Present'.format(host))
        items['insight_rest_hosts'] = '\n'.join(insight_rest_hosts)
    else:
        items['insight_rest_hosts'] = ''

    # Check base templates
    check_templates_errors = []
    for host in insight_zabbix_intersect:
        if host in conf['global']['templates_check_exclude_hosts']:
            continue
        cur_env = PROD_ENV
        host_env_types = set()
        host_env_names = set()
        for env in insight_hosts[host][CARD_ATTR_ENV]:
            host_env_types.add(env['type'])
            host_env_names.add(env['name'])

        if host_env_types and ('PROD' not in host_env_types and 'DEMO' not in host_env_types):
            cur_env = TEST_ENV

        cur_os = insight_hosts[host][CARD_ATTR_OS]
        cur_templates = set(zabbix_hosts[host]['templates'])

        if host_env_names.intersection(conf['global']['wt_env']):
            if 'WhoTrades' not in zabbix_hosts[host]['groups']:
                check_templates_errors.append(
                    '{0},{1},{2},узел не содержит группу WhoTrades'.format(host, cur_env, 'WT')
                )
            if cur_env == PROD_ENV:
                if cur_os == 'Linux':
                    base_template = conf['global']['wt_templates_prod_lin']
                elif cur_os == 'Windows':
                    base_template = conf['global']['prod_templates_win']
                else:
                    continue

                if not cur_templates.intersection(base_template):
                    check_templates_errors.append(
                        '{0},{1},{2},не содержит базовый шаблон {3} для {4}'.format(
                            host, cur_env, 'WT', ', '.join(base_template), cur_os
                        )
                    )
            else:
                if cur_os == 'Linux':
                    base_template = conf['global']['wt_templates_test_lin']
                elif cur_os == 'Windows':
                    base_template = conf['global']['test_templates_win']
                else:
                    continue

                if not cur_templates.intersection(base_template):
                    check_templates_errors.append(
                        '{0},{1},{2},не содержит базовый шаблон {3} для {4}'.format(
                            host, cur_env, 'WT', ', '.join(base_template), cur_os
                        )
                    )
        else:
            if cur_env == PROD_ENV:
                if cur_os == 'Linux':
                    base_template = conf['global']['prod_templates_lin']
                elif cur_os == 'Windows':
                    base_template = conf['global']['prod_templates_win']
                else:
                    continue

                if not cur_templates.intersection(base_template):
                    check_templates_errors.append(
                        '{0},{1},{2},не содержит базовый шаблон {3}'
                        ' для {4}'.format(host, cur_env, 'не WT', ', '.join(base_template), cur_os)
                    )
            else:
                if cur_os == 'Linux':
                    base_template = conf['global']['test_templates_lin']
                elif cur_os == 'Windows':
                    base_template = conf['global']['test_templates_win']
                else:
                    continue

                if not cur_templates.intersection(base_template):
                    check_templates_errors.append(
                        '{0},{1},{2},не содержит базовый шаблон {3}'
                        ' для {4}'.format(host, cur_env, 'не WT', ', '.join(base_template), cur_os)
                    )
    # print(json.dumps(check_templates_errors, indent=4, ensure_ascii=False))
    items['templates_check'] = '\n'.join(check_templates_errors)

    for host_to_remove in hosts_to_remove:
        host_seen_counter.pop(host_to_remove)
    for host in host_seen_counter:
        host_seen_counter[host] += 1
    for hosts_to_add in hosts_to_add:
        host_seen_counter[hosts_to_add] = 1
    redis_client.set(name='host_seen_counter', value=json.dumps(host_seen_counter))

    zbx_container = DataContainer()
    zbx_container.server_active = '127.0.0.1'
    zbx_container.server_port = 10051
    zbx_container.data_type = 'items'
    zbx_data = {args.s: items}
    zbx_container.add(zbx_data)
    zbx_container.send()
    return ''


def main():
    parser = argparse.ArgumentParser(description='Compare vCenters & Insight')

    subparsers = parser.add_subparsers(help='Collect hosts data / Compare hosts data')

    parser_1 = subparsers.add_parser('collect', help='Collect data from sites')
    parser_1.add_argument('-s', help='Sender host', required=True)
    parser_1.add_argument('--gconfig', help='Global configuration file', required=False,
                          default='inf_compare_global.conf')
    parser_1.add_argument('--config', help='Sites configuration file', required=False,
                          default='inf_compare_cfg.conf')
    parser_1.set_defaults(func=collect)

    parser_2 = subparsers.add_parser('compare', help='Compare data')
    parser_2.add_argument('-s', help='Sender host', required=True)
    parser_2.add_argument('--gconfig', help='Global configuration file', required=False,
                          default='inf_compare_global.conf')
    parser_2.set_defaults(func=compare)

    parser_3 = subparsers.add_parser('discover', help='Discover sites')
    parser_3.add_argument('--redis', required=False, default='127.0.0.1')
    parser_3.set_defaults(func=discover)

    args = parser.parse_args()
    print(args.func(args))


if __name__ == '__main__':
    main()
