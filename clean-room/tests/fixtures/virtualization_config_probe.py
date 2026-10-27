#!/usr/bin/env python3
"""Validate a signed, networkless VZ configuration without creating a VM."""
import pathlib
import subprocess
import tempfile

SWIFT = r'''import Foundation
import Virtualization
let config = VZVirtualMachineConfiguration()
config.bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: CommandLine.arguments[1]))
config.cpuCount = VZVirtualMachineConfiguration.minimumAllowedCPUCount
config.memorySize = VZVirtualMachineConfiguration.minimumAllowedMemorySize
print("virtualization_supported=\(VZVirtualMachine.isSupported)")
do { try config.validate(); print("configuration_validated=true") }
catch { print("configuration_validated=false: \(error)"); exit(1) }
'''
ENTITLEMENTS = '''<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.virtualization</key><true/></dict></plist>'''

with tempfile.TemporaryDirectory(prefix="sf-vz-config-") as temporary:
    root = pathlib.Path(temporary)
    (root / "probe.swift").write_text(SWIFT)
    (root / "entitlements.plist").write_text(ENTITLEMENTS)
    (root / "dummy-kernel").write_text("This is not a bootable kernel.\n")
    binary = str(root / "probe")
    commands = [
        ["xcrun", "swiftc", str(root / "probe.swift"), "-o", binary, "-framework", "Virtualization"],
        ["codesign", "--force", "--sign", "-", "--entitlements", str(root / "entitlements.plist"), binary],
        ["codesign", "-d", "--entitlements", "-", binary],
        [binary, str(root / "dummy-kernel")],
    ]
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        print(result.stdout + result.stderr, end="")
        if result.returncode:
            raise SystemExit(result.returncode)
