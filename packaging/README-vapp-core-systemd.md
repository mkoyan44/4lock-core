# vapp-core-daemon systemd service

Run vapp-core-daemon as a system service under user/group **vapp:vapp**.

## Install path and socket

- **Binary**: `/usr/local/lib/4lock/vapp-core-daemon` (override via systemd unit or Ansible vars).
- **Socket**: `/run/vapp/vapp-core.sock` (created by systemd `RuntimeDirectory=vapp`).
- **State**: `/var/lib/vapp` (bundles, CRI socket, app data).

## Client connection

vapp and vappd resolve the socket in this order:

1. `VAPPC_SOCKET` environment variable (or equivalent for vapp-core)
2. `vappc_share_dir()/vapp-core.sock` (Linux)
3. `/run/vapp/vapp-core.sock` if it exists (systemd service)
4. `/tmp/vapp-core.sock` (default)

To let a user run vapp/vappd and connect to the system daemon, add them to the **vapp** group:

```bash
sudo usermod -aG vapp <username>
```

Then log out and back in (or `newgrp vapp`).

## Install (manual)

1. Create group and user:
   ```bash
   sudo groupadd -r vapp
   sudo useradd -r -g vapp -s /usr/sbin/nologin -d /var/lib/vapp vapp
   ```

2. Create dirs and install binary:
   ```bash
   sudo mkdir -p /usr/local/lib/4lock /var/lib/vapp
   sudo cp target/release/vapp-core-daemon /usr/local/lib/4lock/
   sudo chmod 755 /usr/local/lib/4lock/vapp-core-daemon
   sudo chown -R vapp:vapp /var/lib/vapp
   ```

3. Install unit and start:
   ```bash
   sudo cp packaging/systemd/vapp-core-daemon.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now vapp-core-daemon.service
   ```

## Install (Ansible, 4lock-de)

From 4lock-de repo, run the playbook (optionally set `vappcore_binary_src` to the built binary path; playbook may use `vappc_binary_src` until 4lock-de is updated):

```bash
ansible-playbook -i clusters/production-onprem-shared/ansible/inventory.ini \
  clusters/production-onprem-shared/ansible/playbooks/vappc-daemon.yml \
  -e vappcore_binary_src=/path/to/vapp-core-daemon
```

If the binary path var is omitted, the binary must already be present at `/usr/local/lib/4lock/vapp-core-daemon`.

## Privileged vs rootless

When the daemon runs as **root** (e.g. for testing), system requirements check is skipped and privileged containers can be used. When it runs as **vapp**, the daemon still runs the rootless-oriented check unless you run the Linux container setup script (subuid, subgid) for rootless mode, or run the service as root for privileged mode.
