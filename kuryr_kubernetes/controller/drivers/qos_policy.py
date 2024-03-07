# Copyright 2018 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress
import netaddr

from openstack import exceptions as os_exc
from oslo_log import log as logging

from kuryr_kubernetes import clients
from kuryr_kubernetes import config
from kuryr_kubernetes import constants
from kuryr_kubernetes.controller.drivers import base
from kuryr_kubernetes.controller.drivers import utils as driver_utils
from kuryr_kubernetes import exceptions
from kuryr_kubernetes import utils

CONF = config.CONF

LOG = logging.getLogger(__name__)


class QosPolicyDriver(base.QosPolicyDriver):
    """Provide Qos actions based on K8s pod annotations"""

    def __init__(self):
        super().__init__()
        self.os_net = clients.get_network_client()
        self.kubernetes = clients.get_kubernetes_client()

    def create_qos_policy_rule(self, pod, qos_policy):
        ingress_rate, egress_rate = self.get_pod_limit_rate(pod)

        if ingress_rate is not None:
            try:
                in_rate = int(ingress_rate) * 1000
            except ValueError:
                LOG.exception("The pod %s: ingress_rate %s value is illegal", pod['metadata']['name'], ingress_rate)
                raise

            ingress_rule = {
                "max_kbps": in_rate,
                "direction": "ingress"
            }
            ingress_policy_rule = self.os_net.create_qos_bandwidth_limit_rule(qos_policy.id, **ingress_rule)
            LOG.debug("pod %s: ingress rate rule has been created, %s", pod['metadata']['name'], ingress_policy_rule)

        if egress_rate is not None:
            try:
                eg_rate = int(egress_rate) * 1000
            except ValueError:
                LOG.exception("The pod %s: egress_rate %s value is illegal", pod['metadata']['name'], egress_rate)
                raise

            egress_rule = {
                "max_kbps": eg_rate,
                "direction": "egress"
            }
            egress_policy_rule = self.os_net.create_qos_bandwidth_limit_rule(qos_policy, **egress_rule)
            LOG.debug("pod %s: egress rate rule has been created, %s", pod['metadata']['name'], egress_policy_rule)

            return qos_policy

    def update_qos_policy_rule(self, pod, qos_policy):
        rules = {}
        try:
            qos_policy_rules = self.os_net.qos_bandwidth_limit_rules(qos_policy=qos_policy.id)
        except os_exc.SDKException:
            LOG.exception("Error geting qos policy "
                          " %s", pod['metadata']['name'])
            raise
        for rule in qos_policy_rules:
            self.os_net.delete_qos_bandwidth_limit_rule(rule.id, qos_policy.id)

        qos_policy = self.create_qos_policy_rule(pod, qos_policy)

        return qos_policy

    def release_qos_policy(self, pod):
        owner_name = driver_utils.get_owner_references_name(pod)
        if not owner_name:
            owner_name = pod['metadata']['name']
        qos_policy_name = ("qos-" + pod['metadata']['namespace'] + "-" +
                           owner_name)
        try:
            qos_policy = self.os_net.find_qos_policy(qos_policy_name)
            LOG.debug("release qos policy. pod name is %s, qos policy name is %s. qos_policy is %s", pod['metadata']['name'],
                      qos_policy_name, qos_policy)
        except os_exc.SDKException:
            LOG.exception("Error getting qos policy "
                          " %s", pod['metadata']['name'])
            raise

        if qos_policy is None:
            return

        try:
            self.os_net.delete_qos_policy(qos_policy.id)
        except os_exc.ConflictException:
            LOG.debug("The Qos policy %s has been used by other port", qos_policy.id)
            return

    def _check_qos_policy_is_match(self, pod):
        changed = False
        metadata = pod['metadata']
        ingress_rate = metadata.get("annotations", {}).get(constants.K8S_ANNOTATION_INGRESS_RATE)
        egress_rate = metadata.get("annotations", {}).get(constants.K8S_ANNOTATION_EGRESS_RATE)

        owner_name = driver_utils.get_owner_references_name(pod)
        if not owner_name:
            owner_name = pod['metadata']['name']
        qos_policy_name = ("qos-" + pod['metadata']['namespace'] + "-" +
                           owner_name)
        try:
            qos_policy = self.os_net.find_qos_policy(qos_policy_name)
        except (os_exc.SDKException, exceptions.ResourceNotReady):
            LOG.exception("Error geting qos policy "
                          " %s", pod['metadata']['name'])
            raise
        LOG.debug("Pod name is %s, qos policy  is %s", metadata['name'], qos_policy)

        if qos_policy is None:
            return None, changed

        try:
            qos_policy_rules = self.os_net.qos_bandwidth_limit_rules(qos_policy=qos_policy.id)
        except os_exc.SDKException:
            LOG.exception("Error getting qos policy "
                          " %s", pod['metadata']['name'])
            raise

        for rule in qos_policy_rules:
            LOG.debug("qos policy name is %s, qos policy rule is %s", qos_policy.name, rule)
            if rule.direction == 'ingress':
                if ingress_rate is None:
                    return qos_policy, True
                in_rate = int(ingress_rate) * 1000
                if rule.max_kbps != in_rate:
                    return qos_policy, True

            if rule.direction == 'egress':
                if egress_rate is None:
                    return qos_policy, True
                e_rate = int(egress_rate) * 1000
                if rule.max_kbps != e_rate:
                    return qos_policy, True

        return qos_policy, False

    def create_qos_policy(self, pod, project_id):
        owner_name = driver_utils.get_owner_references_name(pod)
        if not owner_name:
            owner_name = pod['metadata']['name']
        qos_policy_name = ("qos-" + pod['metadata']['namespace'] + "-" +
                           owner_name)
        desc = ("Kuryr-Kubernetes Qos Policy %s Qos" %
                owner_name)

        try:
            qos_policy = self.os_net.create_qos_policy(name=qos_policy_name,
                                                       project_id=project_id,
                                                       description=desc)
            driver_utils.tag_neutron_resources([qos_policy])
        except (os_exc.SDKException, exceptions.ResourceNotReady):
            LOG.exception("Error creating qos policy "
                          " %s", pod['metadata']['name'])
            raise

        return qos_policy

    def get_qos_policy(self, pod, project_id):
        metadata = pod['metadata']
        ingress_rate = metadata.get("annotations", {}).get(constants.K8S_ANNOTATION_INGRESS_RATE)
        egress_rate = metadata.get("annotations", {}).get(constants.K8S_ANNOTATION_EGRESS_RATE)

        if ingress_rate is None and egress_rate is None:
            return None

        qos_policy, changed = self._check_qos_policy_is_match(pod)
        LOG.debug("Pod name is %s, ingress_rate is %s, egress_rate is %s, qos_policy is %s, changed is %s",
                  pod['metadata']['name'], ingress_rate, egress_rate, qos_policy, changed)

        if qos_policy is not None and changed is False:
            return qos_policy

        if qos_policy is None:
            # Create Qos policy, qos policy name key is owner name.
            qos_policy = self.create_qos_policy(pod, project_id)
            # Create Qos policy rule, need ingress rate or egress rate
            qos_policy = self.create_qos_policy_rule(pod, qos_policy)

        elif qos_policy is not None and changed is True:
            qos_policy = self.update_qos_policy_rule(pod, qos_policy)

        return qos_policy

    def get_pod_limit_rate(self, pod):
        metadata = pod['metadata']
        ingress_rate = metadata.get("annotations", {}).get(constants.K8S_ANNOTATION_INGRESS_RATE)
        egress_rate = metadata.get("annotations", {}).get(constants.K8S_ANNOTATION_EGRESS_RATE)

        return ingress_rate, egress_rate
