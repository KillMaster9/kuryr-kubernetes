import json
from typing import List, Dict
from kuryr_kubernetes import clients

# Assuming equivalent types.ResourceClient and types.ResourceInfo definitions are imported or defined elsewhere.

checkpoint_file = "/var/lib/kubelet/device-plugins/kubelet_internal_checkpoint"


class PodDevicesEntry:
    def __init__(self, pod_uid: str, container_name: str, resource_name: str, device_ids: List[str], alloc_resp: bytes):
        self.PodUID = pod_uid
        self.ContainerName = container_name
        self.ResourceName = resource_name
        self.DeviceIDs = device_ids
        self.AllocResp = alloc_resp


class CheckpointPodResourcesClient:
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.pod_entries = []

    def get_pod_entries(self):
        try:
            with open(self.file_name, 'r') as f:
                data = json.load(f)
                self.pod_entries = data['Data']['PodDeviceEntries']
                print(f"get_pod_entries: pod_entries {self.pod_entries}")
        except Exception as e:
            print(f"get_pod_entries: error reading or parsing file {self.file_name}: {str(e)}")

    def get_pod_resource_map(self, pod_link):
        k8s = clients.get_kubernetes_client()
        pod = k8s.get(pod_link)

        pod_id = pod['metadata']['uid']
        resource_map: Dict[str, List[str]] = {}

        if not pod_id:
            raise ValueError("get_pod_resource_map: invalid Pod UID")

        for entry in self.pod_entries:
            if entry['PodUID'] == pod_id:
                if entry['ResourceName'] in resource_map:
                    resource_map[entry['ResourceName']].extend(list(entry["DeviceIDs"].values()))
                else:
                    resource_map[entry['ResourceName']] = list(entry["DeviceIDs"].values())

        return resource_map


def get_checkpoint() -> CheckpointPodResourcesClient:
    return get_checkpoint_from_file(checkpoint_file)


def get_checkpoint_from_file(file_path: str) -> CheckpointPodResourcesClient:
    cp = CheckpointPodResourcesClient(file_path)
    cp.get_pod_entries()
    print(f"get_checkpoint_from_file: created checkpoint instance with file: {file_path}")
    return cp
