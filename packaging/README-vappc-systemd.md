# vappc-linux-daemon systemd service

Run vappc-linux-daemon as a system service under user/group **vapp:vapp**.

## Install path and socket

- **Binary**: `/usr/local/lib/4lock/vappc-linux-daemon` (override via systemd unit or Ansible vars).
- **Socket**: `/run/vapp/vappc.sock` (created by systemd `RuntimeDirectory=vapp`).
- **State**: `/var/lib/vapp` (bundles, CRI socket, app data).

## Client connection

vapp and vappd resolve the socket in this order:

1. `VAPPC_SOCKET` environment variable
2. `vappc_share_dir()/vappc.sock` (Linux)
3. `/run/vapp/vappc.sock` if it exists (systemd service)
4. `/tmp/vappc.sock` (default)

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
   sudo cp target/release/vappc-linux-daemon /usr/local/lib/4lock/
   sudo chmod 755 /usr/local/lib/4lock/vappc-linux-daemon
   sudo chown -R vapp:vapp /var/lib/vapp
   ```

3. Install unit and start:
   ```bash
   sudo cp packaging/systemd/vappc-linux-daemon.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now vappc-linux-daemon.service
   ```

## Install (Ansible, 4lock-de)

From 4lock-de repo, run the playbook (optionally set `vappc_binary_src` to the built binary path):

```bash
ansible-playbook -i clusters/production-onprem-shared/ansible/inventory.ini \
  clusters/production-onprem-shared/ansible/playbooks/vappc-daemon.yml \
  -e vappc_binary_src=/path/to/vappc-linux-daemon
```

If `vappc_binary_src` is omitted, the binary must already be present at `/usr/local/lib/4lock/vappc-linux-daemon`.

## Privileged vs rootless

When the daemon runs as **root** (e.g. for testing), system requirements check is skipped and privileged containers can be used. When it runs as **vapp**, the daemon still runs the rootless-oriented check unless you run the Linux container setup script (subuid, subgid, passt) for rootless mode, or run the service as root for privileged mode.
