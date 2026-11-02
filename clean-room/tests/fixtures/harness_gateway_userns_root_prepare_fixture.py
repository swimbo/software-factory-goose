#!/usr/bin/env python3
"""Native private launcher replay with synthetic authority and cgroup attachment."""

import json
import os
import shutil

import harness_gateway_exec_replay as fixture


def main():
    if os.geteuid() != 0 or os.environ.get("SFACTORY_USERNS_PREPARE_FIXTURE") != "1":
        raise RuntimeError("explicit disposable Root fixture required")
    fixture.ROOT.mkdir(parents=True, mode=0o755)
    shutil.copyfile("/fixture/sfactory-userns-gateway-target", fixture.TARGET)
    fixture.TARGET.chmod(0o555)
    fixture.prepare_case()
    fixture.prepare_case(refuse=True)
    fixture.prepare_case(refuse_guard=True)
    fixture.prepare_case(refuse_map_guard=True)
    fixture.prepare_case(release=True)
    print(
        json.dumps(
            {
                "actual_private_prepare_and_release": True,
                "attachment_refusal_child_joined": True,
                "guard_loss_child_joined": True,
                "guard_loss_after_mapping_child_joined": True,
                "broker_peer_verified": True,
                "synthetic_authority_and_attachment": True,
                "production_admission": False,
                "paid_calls": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
