#!/bin/sh
set -eu

build_dir=${OIS_BUILD_DIR:-/build}
runtime_dir=$(mktemp -d)
cleanup()
{
    if [ -f "$runtime_dir/avahi.pid" ]; then
        kill "$(cat "$runtime_dir/avahi.pid")" 2>/dev/null || true
    fi
    if [ -f "$runtime_dir/dbus.pid" ]; then
        kill "$(cat "$runtime_dir/dbus.pid")" 2>/dev/null || true
    fi
    rm -rf "$runtime_dir"
}
trap cleanup EXIT INT TERM

mkdir -p /run/dbus
install -d -o avahi -g avahi -m 755 /run/avahi-daemon
export XDG_RUNTIME_DIR=/run/user/0
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket
cat >"$runtime_dir/dbus.conf" <<'EOF'
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
EOF
dbus-daemon --fork \
    --config-file="$runtime_dir/dbus.conf" \
    --print-pid=1 >"$runtime_dir/dbus.pid"

ip link add ois0 type dummy
ip address add 10.77.0.2/24 dev ois0
ip link set dev ois0 multicast on
ip link set dev ois0 up

cat >"$runtime_dir/avahi-daemon.conf" <<'EOF'
[server]
host-name=fixture
domain-name=local
use-ipv4=yes
use-ipv6=no
allow-interfaces=ois0
enable-dbus=yes

[wide-area]
enable-wide-area=no

[publish]
publish-addresses=yes
publish-hinfo=no
publish-workstation=no
publish-domain=yes

[reflector]
enable-reflector=no
EOF

avahi-daemon --debug --no-chroot \
    --file="$runtime_dir/avahi-daemon.conf" \
    >"$runtime_dir/avahi.log" 2>&1 &
echo "$!" >"$runtime_dir/avahi.pid"

attempt=0
until dbus-send --system --print-reply \
    --dest=org.freedesktop.Avahi / org.freedesktop.Avahi.Server.GetVersionString \
    >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "controlled Avahi daemon did not become ready" >&2
        sed -n '1,80p' "$runtime_dir/avahi.log" >&2
        exit 1
    fi
    sleep 0.1
done

ctest --test-dir "$build_dir" --output-on-failure \
    -R '^mdns_(resolver_contract|controlled_responder)$'
