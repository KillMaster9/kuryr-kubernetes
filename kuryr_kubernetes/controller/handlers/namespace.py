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

from oslo_log import log as logging

from kuryr_kubernetes import clients
from kuryr_kubernetes import constants
from kuryr_kubernetes.controller.drivers import base as drivers
from kuryr_kubernetes import exceptions
from kuryr_kubernetes.handlers import k8s_base
from kuryr_kubernetes import utils
from oslo_serialization import jsonutils
from kuryr_kubernetes.controller.drivers import utils as driver_utils


LOG = logging.getLogger(__name__)


class NamespaceHandler(k8s_base.ResourceEventHandler):
    OBJECT_KIND = constants.K8S_OBJ_NAMESPACE
    OBJECT_WATCH_PATH = constants.K8S_API_NAMESPACES

    def __init__(self):
        super(NamespaceHandler, self).__init__()
        self._drv_project = drivers.NamespaceProjectDriver.get_instance()

    def on_present(self, namespace, *args, **kwargs):
        ns_labels = namespace['metadata'].get('labels', {})
        ns_name = namespace['metadata']['name']
        kns_crd = self._get_kns_crd(ns_name)
        if kns_crd:
            LOG.debug("Previous CRD existing at the new namespace.")
            self._update_labels(kns_crd, ns_labels)
            return

        try:
            self._add_kuryrnetwork_crd(ns_name, ns_labels)
        except exceptions.K8sClientException:
            LOG.exception("Kuryrnetwork CRD creation failed.")
            raise exceptions.ResourceNotReady(namespace)

    def _update_labels(self, kns_crd, ns_labels):
        kns_status = kns_crd.get('status')
        if kns_status:
            kns_crd_labels = kns_crd['status'].get('nsLabels', {})
            if kns_crd_labels == ns_labels:
                # Labels are already up to date, nothing to do
                return

        kubernetes = clients.get_kubernetes_client()
        LOG.debug('Patching KuryrNetwork CRD %s', kns_crd)
        try:
            kubernetes.patch_crd('spec', utils.get_res_link(kns_crd),
                                 {'nsLabels': ns_labels})
        except exceptions.K8sResourceNotFound:
            LOG.debug('KuryrNetwork CRD not found %s', kns_crd)
        except exceptions.K8sClientException:
            LOG.exception('Error updating kuryrnetwork CRD %s', kns_crd)
            raise

    def _get_kns_crd(self, namespace):
        k8s = clients.get_kubernetes_client()
        try:
            kuryrnetwork_crd = k8s.get('{}/{}/kuryrnetworks/{}'.format(
                constants.K8S_API_CRD_NAMESPACES, namespace,
                namespace))
        except exceptions.K8sResourceNotFound:
            return None
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception.")
            raise
        return kuryrnetwork_crd

    def _add_kuryrnetwork_crd(self, namespace, ns_labels):
        project_id = self._drv_project.get_project(namespace)
        kubernetes = clients.get_kubernetes_client()

        kns_crd = {
            'apiVersion': 'openstack.org/v1',
            'kind': 'KuryrNetwork',
            'metadata': {
                'name': namespace,
                'finalizers': [constants.KURYRNETWORK_FINALIZER],
            },
            'spec': {
                'nsName': namespace,
                'projectId': project_id,
                'nsLabels': ns_labels,
            }
        }
        try:
            kubernetes.post('{}/{}/kuryrnetworks'.format(
                constants.K8S_API_CRD_NAMESPACES, namespace), kns_crd)
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception creating kuryrnetwork "
                          "CRD.")
            raise

    def is_ready(self, quota):
        if not (utils.has_kuryr_crd(constants.K8S_API_CRD_KURYRNETWORKS) and
                self._check_quota(quota)):
            LOG.error('Marking NamespaceHandler as not ready.')
            return False
        return True

    def _check_quota(self, quota):
        resources = ('subnets', 'networks', 'security_groups')

        for resource in resources:
            resource_quota = quota[resource]
            if utils.has_limit(resource_quota):
                if not utils.is_available(resource, resource_quota):
                    return False
        return True


class IcsNamespaceHandler(k8s_base.ResourceEventHandler):
    OBJECT_KIND = constants.K8S_OBJ_NAMESPACE
    OBJECT_WATCH_PATH = constants.K8S_API_NAMESPACES

    def __init__(self):
        super(IcsNamespaceHandler, self).__init__()
        #self._drv_project = drivers.NamespaceProjectDriver.get_instance()
        self._drv_sg = drivers.PodSecurityGroupsDriver.get_instance()

    def on_present(self, namespace, *args, **kwargs):
        name = namespace['metadata']['name']
        current_ns_labels = namespace['metadata'].get('labels', {})
        previous_ns_label = self._get_namespace_info(namespace)

        LOG.debug("Got Namespace labels, namspace name is %s, current namespace label is %s, previous namespace "
                  "labels is %s", name, current_ns_labels, previous_ns_label)

        if previous_ns_label == current_ns_labels:
            return

        self._drv_sg.update_namespace_sg_rules(namespace)

        try:
            self._set_namespace_info(namespace, current_ns_labels)
        except exceptions.K8sResourceNotFound:
            LOG.debug("Namespace already deleted, no need to retry.")
            return

    def _get_namespace_info(self, namespace):
        try:
            annotations = namespace['metadata']['annotations']
            namespace_labels_annotation = annotations[constants.K8S_ANNOTATION_NAMESPACE_LABEL]
        except KeyError:
            return None, None
        pod_labels = jsonutils.loads(namespace_labels_annotation)
        return pod_labels

    def _set_namespace_info(self, namespace, info):
        if not info:
            LOG.debug("Removing info annotations: %r", info)
            annotation = None
        else:
            annotation = jsonutils.dumps(info, sort_keys=True)
            LOG.debug("Setting info annotations: %r", annotation)

        k8s = clients.get_kubernetes_client()
        k8s.annotate(utils.get_res_link(namespace),
                     {
                         constants.K8S_ANNOTATION_NAMESPACE_LABEL: annotation,
                     },
                     resource_version=namespace['metadata']['resourceVersion'])

    def on_deleted(self, namespace, *args, **kwargs):
        if driver_utils.is_network_policy_enabled():
            self._drv_sg.delete_namespace_sg_rules(namespace)
