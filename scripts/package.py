#!/usr/bin/env python3
"""Create beta bundles with artifacts for explicit SSH bootstrap."""
import hashlib
import json
from pathlib import Path
import zipfile

dist = Path(__file__).resolve().parent.parent / "dist"
targets = [("windows", "amd64"), ("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64")]
helpers = [dist / f"tslink-{system}-{arch}" for system, arch in targets if system != "windows"]
bundles = []
for system, arch in targets:
    executable = dist / (f"tslink-{system}-{arch}" + (".exe" if system == "windows" else ""))
    path = dist / f"tslink-{system}-{arch}-bundle.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(executable, "tslink.exe" if system == "windows" else "tslink")
        for helper in helpers:
            archive.write(helper, f"delivery/{helper.name}")
        archive.writestr("START.txt", """Tailscale LinkPilot - third-party private beta
Install once: tslink install
Start background: tslink start
Stop background (keep config): tslink stop
Restart background: tslink restart
Check state: tslink status
Choose a peer: tslink connect <peer>
Missing peer helper: tslink connect <peer> --ssh <management-login>
SSH requires your own management access; no password is saved.
Existing helpers accept new authorization without restart.
Windows: install as administrator; the task runs at user login.
Daily start/stop/restart use the installed user background service; they do not reinstall.
Stop ends the current run; the next login still starts the installed service.
Linux: coordination responder in this release.
macOS: install asks once for admin authorization of the protected discovery-only capture helper.
macOS: daily optimization uses a user LaunchAgent; keep the user logged in and Mac awake.
macOS: the first privileged setup on a remote Mac needs an interactive local install.
New session search currently targets Linux with public physical IPv4.
Windows SSH deployment and invitation links are not implemented.
""")
    bundles.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
(dist / "bundles.json").write_text(json.dumps({"product": "Tailscale LinkPilot", "bundles": bundles}, indent=2) + "\n")
print(f"Packaged {len(bundles)} beta bundles.")
