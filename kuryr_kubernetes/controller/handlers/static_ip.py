# Copyright (c) 2016 Mirantis, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from netaddr import IPNetwork, IPAddress, core
from kuryr_kubernetes import constants
from oslo_config import cfg
from oslo_log import log
from kuryr_kubernetes import clients
from openstack import exceptions as os_exc
from os_vif.objects import fixed_ip as osv_fixed_ip
from kuryr_kubernetes import exceptions

LOG = log.getLogger(__name__)

CONF = cfg.CONF


def acquire_pod_address(pod, networks):
    subnet_version = {}
    ipv4, ipv6 = "", ""
    os_net = clients.get_network_client()

    # 1. get init data
    # format 10.1.1.1,2024::1
    # format 10.1.1.1,10.1.1.2,10.1.1.3 or 10.1.1.1,2024::1;10.1.1.2,2024::2
    metadata = pod['metadata']
    pod_ip_address = metadata.get('annotations', {}).get(constants.K8S_ANNOTATION_IP_ADDRESS)
    pod_ip_pool = metadata.get('annotations', {}).get(constants.K8S_ANNOTATION_IP_POOL)
    LOG.debug("Pod name is %s, annotations pod_ip_address is %s, pod_ip_pool is %s", pod['metadata']['name'],
              pod_ip_address, pod_ip_pool)

    if not pod_ip_address and not pod_ip_pool:
        return networks

    for subnet_id, network in networks.items():
        subnet = os_net.get_subnet(subnet_id)
        if subnet is not None:
            subnet_version.setdefault(subnet.ip_version, {}).setdefault(subnet_id, subnet.cidr)

    if pod_ip_address:
        ipv4, ipv6 = acquire_static_ip_address(pod_ip_address, subnet_version)
        if not ipv4 and not ipv6:
            raise exceptions.ResourceNotReady(pod)
        LOG.debug("Pod name is %s, pod_ip_address is %s,%s", pod['metadata']['name'], ipv4, ipv6)
        networks = populate_networks_fixed_ips(ipv4, ipv6, networks)
        return networks

    ip_pool = []
    if pod_ip_pool:
        if pod_ip_pool.find(';') != -1:
            ip_pool = pod_ip_pool.split(';')
        else:
            ip_pool = pod_ip_pool.split(',')
            if len(ip_pool) == 2 and IPAddress(ip_pool[0]).version != IPAddress(ip_pool[1]).version:
                ip_pool = [pod_ip_pool]

    is_sts, sts_name = is_stateful_set_pod(pod)
    if is_sts is False:
        for ip in ip_pool:
            ipv4, ipv6 = acquire_static_ip_address(ip, subnet_version)
            if ((ipv4 or ipv6) and len(networks) == 1) or (ipv4 and ipv6 and len(networks) == 2):
                networks = populate_networks_fixed_ips(ipv4, ipv6, networks)
                return networks
    else:
        pod_name = pod['metadata']['name']
        index = int(pod_name.split('-')[-1])
        if index < len(ip_pool):
            ipv4, ipv6 = acquire_static_ip_address(ip_pool[index], subnet_version)
            if ((ipv4 or ipv6) and len(networks) == 1) or (ipv4 and ipv6 and len(networks) == 2):
                networks = populate_networks_fixed_ips(ipv4, ipv6, networks)
                return networks

    raise exceptions.ResourceNotReady(pod)


def acquire_static_ip_address(ip_address, subnet_version):
    ipv4, ipv6 = "", ""
    os_net = clients.get_network_client()
    ips = ip_address.split(',')

    for ip in ip_address.split(','):
        try:
            addr = IPAddress(ip)
        except core.AddrFormatError:
            LOG.error("Pod IP address %s format error.", ip)
            continue
        try:
            cidr = list(dict(subnet_version[addr.version]).values())[0]
            network = IPNetwork(cidr)
        except core.AddrFormatError:
            LOG.error("network IP address %s format error.")
            continue

        # check the ip from the network
        if addr not in network:
            LOG.error("The addr %s not belong to the network %s", addr, cidr)
            continue

        # check the ip inuse
        subnet_id = list(dict(subnet_version[addr.version]).keys())[0]
        LOG.debug("Pod static ip %s, subnet id %s", ip, subnet_id)
        try:
            fixed_ips = ['subnet_id=%s' % str(subnet_id),
                         'ip_address=%s' % str(ip)]
            ports = os_net.ports(fixed_ips=fixed_ips)
        except os_exc.ResourceNotFound:
            # ip not use, the fixed_ip can use the pod
            if addr.version == constants.IP_VERSION_4:
                ipv4 = ip
            if addr.version == constants.IP_VERSION_6:
                ipv6 = ip
            LOG.debug("The Pod ip %s is valid", ip)
        except os_exc.SDKException:
            LOG.error("Port with fixed ips %s not found!", fixed_ips)
            return "", ""
        try:
            pts = next(ports)
        except StopIteration:
            pts = None
        if pts:
            LOG.error("Port IP %s has been used by other port", addr)
            continue
        else:
            if addr.version == constants.IP_VERSION_4:
                ipv4 = ip
            if addr.version == constants.IP_VERSION_6:
                ipv6 = ip
            LOG.debug("The Pod ip %s is valid", ip)

    if len(subnet_version) == 1 and ipv4:
        return ipv4, ""
    if len(subnet_version) == 1 and ipv6:
        return "", ipv6
    if len(subnet_version) == 2 and IPAddress(ips[0]).version != IPAddress(ips[1]).version and ipv4 and ipv6:
        return ipv4, ipv6

    return "", ""


def populate_networks_fixed_ips(ipv4, ipv6, networks):
    if not ipv4 and not ipv6:
        return networks

    for subnet_id, network in networks.items():
        if len(network.subnets.objects) > 1:
            return networks
        for subnet in network.subnets.objects:
            if subnet.obj_attr_is_set('ips') is False:
                subnet.ips = osv_fixed_ip.FixedIPList(objects=[])
            if IPNetwork(subnet.cidr).version == constants.IP_VERSION_4:
                subnet.ips.objects.append(osv_fixed_ip.FixedIP(address=str(ipv4)))
            if IPNetwork(subnet.cidr).version == constants.IP_VERSION_6:
                subnet.ips.objects.append(osv_fixed_ip.FixedIP(address=str(ipv6)))
    return networks


def is_stateful_set_pod(pod):
    owner_references = pod['metadata'].get('ownerReferences', [])
    for owner in owner_references:
        if owner['kind'] == "StatefulSet" and owner['apiVersion'].startswith("apps/"):
            if pod['metadata']['name'].startswith(owner['name']):
                return True, owner['name']
    return False, ""


def is_static_ip_pod(pod):
    metadata = pod['metadata']
    pod_ip_address = metadata.get('annotations', {}).get(constants.K8S_ANNOTATION_IP_ADDRESS)
    pod_ip_pool = metadata.get('annotations', {}).get(constants.K8S_ANNOTATION_IP_POOL)
    if pod_ip_pool or pod_ip_address:
        return True
    return False


def get_owner_references_name(resource):
    owner_references = resource['metadata'].get('ownerReferences', [])
    for owner in owner_references:
        return owner['name']

    return None
