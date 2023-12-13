# Copyright 2023 Inspur, Inc.
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

from oslo_log import log as logging
from oslo_config import cfg

from kuryr_kubernetes import clients
from kuryr_kubernetes import constants
from kuryr_kubernetes.controller.drivers import default_subnet
from kuryr_kubernetes import exceptions
from kuryr_kubernetes import utils
from kuryr_kubernetes import config

LOG = logging.getLogger(__name__)


class IcsNamespacePodSubnetDriver(default_subnet.DefaultPodSubnetDriver):
    pod_subnet_annotation = constants.K8s_ANNOTATION_POD_SUBNET

    def get_subnets(self, pod, project_id):
        pod_namespace = pod['metadata']['namespace']
        if not pod_namespace:
            pod_namespace = "default"
        return self.get_namespace_subnet(pod_namespace)

    def get_namespace_subnet(self, namespace, subnet_id=None):
        subnet_map = {}
        if not subnet_id:
            result = self._get_namespace_subnet_id(namespace)
            subnet_ids = result.split(",")
            for subnet_id in subnet_ids:
                subnet_map[subnet_id.strip()] = utils.get_subnet(subnet_id.strip())
            return subnet_map

        return {subnet_id: utils.get_subnet(subnet_id)}

    def _get_namespace_subnet_id(self, namespace):
        kubernetes = clients.get_kubernetes_client()
        try:
            ns_path = f"{constants.K8S_API_NAMESPACES}/{namespace}"
            ns = kubernetes.get(ns_path)
        except exceptions.K8sResourceNotFound:
            LOG.debug("Namespace resource not yet created, retrying...")
            raise exceptions.ResourceNotReady(namespace)
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception.")
            raise

        ns_md = ns['metadata']
        pod_subnet = ns_md.get('annotations', {}).get(self.pod_subnet_annotation)
        if not pod_subnet:
            LOG.debug("Namespace %s has no pod_subnet annotation, try to get "
                      "subnet id from the configuration option.",
                      ns['metadata']['name'])

            pod_subnet = config.CONF.neutron_defaults.pod_subnet
            if not pod_subnet:
                raise cfg.RequiredOptError('pod_subnet',
                                           cfg.OptGroup('neutron_defaults'))

        return pod_subnet


class IcsNamespaceServiceSubnetDriver(default_subnet.DefaultServiceSubnetDriver):
    service_subnet_annotation = constants.K8s_ANNOTATION_SERVICE_SUBNET

    def get_subnets(self, service, project_id):
        namespace = service['metadata']['namespace']
        return self.get_namespace_subnet(namespace)

    def get_namespace_subnet(self, namespace, subnet_id=None):
        if not subnet_id:
            subnet_id = self._get_namespace_subnet_id(namespace)
        return {subnet_id: utils.get_subnet(subnet_id)}

    def _get_namespace_subnet_id(self, namespace):
        kubernetes = clients.get_kubernetes_client()
        try:
            ns_path = f"{constants.K8S_API_NAMESPACES}/{namespace}"
            ns = kubernetes.get(ns_path)
        except exceptions.K8sResourceNotFound:
            LOG.debug("Namespace resource not yet created, retrying...")
            raise exceptions.ResourceNotReady(namespace)
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception.")
            raise

        ns_md = ns['metadata']
        service_subnet = ns_md.get('annotations', {}).get(self.service_subnet_annotation)
        if not service_subnet:
            LOG.debug("Namespace %s has no service_subnet annotation, try to get "
                      "subnet id from the configuration option.",
                      ns['metadata']['name'])

            pod_subnet = config.CONF.neutron_defaults.service_subnet
            if not pod_subnet:
                raise cfg.RequiredOptError('service_subnet',
                                           cfg.OptGroup('neutron_defaults'))

        return service_subnet
