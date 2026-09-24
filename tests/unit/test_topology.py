"""
Unit tests for topology graph and storage-to-application relationship reconstruction.
"""

from serveraudit.topology.graph import TopologyGraph
from serveraudit.topology.storage import build_storage_topology
from serveraudit.topology.services import build_service_topology


def test_storage_topology_chain_reconstruction():
    """Verify reconstruction of Disk -> Partition -> LUKS -> LVM -> FS -> Mount -> Container -> App."""
    graph = TopologyGraph()

    storage_mock = {
        "disks": [
            {
                "name": "nvme0n1",
                "path": "/dev/nvme0n1",
                "size_formatted": "1.00 TB",
                "children": [
                    {
                        "name": "nvme0n1p3",
                        "path": "/dev/nvme0n1p3",
                        "size_formatted": "950.00 GB",
                        "children": [],
                    }
                ],
            }
        ]
    }

    encryption_mock = {
        "encrypted_volumes": [
            {
                "target_name": "luks_root",
                "underlying_device": "/dev/nvme0n1p3",
                "cipher": "aes-xts-plain64",
                "keysize_bits": 512,
            }
        ]
    }

    lvm_mock = {
        "physical_volumes": [
            {"pv_name": "/dev/mapper/luks_root", "vg_name": "vg_ubuntu"}
        ],
        "volume_groups": [
            {"vg_name": "vg_ubuntu"}
        ],
        "logical_volumes": [
            {"lv_name": "lv_appdata", "vg_name": "vg_ubuntu", "dm_path": "/dev/vg_ubuntu/lv_appdata", "lv_size_formatted": "500.00 GB"}
        ],
    }

    filesystems_mock = {
        "mounts": [
            {
                "source": "/dev/vg_ubuntu/lv_appdata",
                "target": "/srv/appdata",
                "fstype": "ext4",
            }
        ],
        "network_mounts": [],
    }

    docker_mock = {
        "containers": [
            {
                "name": "paperless-web",
                "mounts": [
                    {"type": "bind", "source": "/srv/appdata/paperless", "destination": "/usr/src/paperless/data"}
                ],
            }
        ]
    }

    apps_mock = {
        "applications": [
            {
                "name": "Paperless-ngx",
                "container_name": "paperless-web",
            }
        ]
    }

    chains = build_storage_topology(
        storage_data=storage_mock,
        lvm_data=lvm_mock,
        encryption_data=encryption_mock,
        filesystems_data=filesystems_mock,
        docker_data=docker_mock,
        apps_data=apps_mock,
        graph=graph,
    )

    assert len(chains) == 1
    chain = chains[0]
    assert chain["disk"] == "/dev/nvme0n1"
    assert chain["partition"] == "/dev/nvme0n1p3"
    assert chain["luks"] == "/dev/mapper/luks_root"
    assert chain["vg"] == "vg_ubuntu"
    assert chain["lv"] == "/dev/vg_ubuntu/lv_appdata"
    assert chain["mount"] == "/srv/appdata"
    assert chain["container"] == "paperless-web"
    assert chain["app"] == "Paperless-ngx"

    mermaid = graph.to_mermaid()
    assert "flowchart TD" in mermaid
    assert "Paperless" in mermaid
