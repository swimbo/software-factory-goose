"""Frozen generic Phase 11A worker image, separate from legacy deployment pins.

The image supplies Python and an empty /factory directory. Root must still mount
all six reviewed inputs read-only and enforce the existing UID/network/cgroup
recipe. The retained Docker archive restores the exact config ID; loading it
creates no catalog, launch authority, allowance or service activation.
"""

IMAGE_PROFILE_VERSION = 2
WORKER_IMAGE = "sha256:893d9cf783d732690c84fd3d5ee1a34d4a2b01a4ce570c1ec92d087438c0c01a"
BASE_IMAGE = "sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937"
DOCKERFILE_SHA256 = "7ee0563c00c6f104e091a4f01e779ac406c62ebce9cdd9d24e902a66f4ccbfe3"
ARCHIVE_SHA256 = "814482b3cc0121efa2d0bd76b3e1e0753334f46734040f9bd78aaa1fe268dadc"
