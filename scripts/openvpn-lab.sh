#!/bin/sh
# Стенд для проверки системного OpenVPN на Linux (нужны root, openvpn 2.6,
# iproute2, dnsmasq и python3). Сервер OpenVPN с DNS и двумя сайтами
# «компании» работает в network namespace vpnlab:
#   intranet.corp.test → 10.99.0.1   (подсеть 10.99.0.0/16 присылает сервер)
#   public.corp.test   → 203.0.113.10 (вне присланных маршрутов: только по
#                                      привязке к адаптеру OpenVPN)
# Сервер присылает redirect-gateway и block-outside-dns: клиент обязан их
# игнорировать. Логин alice, пароль s3cret.
#
#   scripts/openvpn-lab.sh up DIR    поднять стенд, DIR/client.ovpn — профиль
#   scripts/openvpn-lab.sh down DIR  убрать стенд
#
# Затем:
#   VPNCLIENT_SINGBOX=… VPNCLIENT_OPENVPN_LAB=DIR go test ./internal/app -run SystemOpenVPN
set -eu

cmd=${1:-}
dir=${2:-}
[ -n "$cmd" ] && [ -n "$dir" ] || { echo "использование: $0 up|down DIR" >&2; exit 2; }
ns=vpnlab

down() {
	for pid in "$dir"/*.pid; do
		[ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null || true
	done
	ip netns del "$ns" 2>/dev/null || true
	ip link del vpnlab0 2>/dev/null || true
}

if [ "$cmd" = down ]; then
	down
	exit 0
fi
[ "$cmd" = up ] || { echo "неизвестная команда $cmd" >&2; exit 2; }

mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
down

cd "$dir"
ec() { openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=vpnlab-ca 2>/dev/null
ec server
printf 'extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyAgreement\n' >server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile server.ext 2>/dev/null
ec client
printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' >client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 2 -extfile client.ext 2>/dev/null

cat >auth.sh <<'EOF'
#!/bin/sh
[ "$(sed -n 1p "$1")" = alice ] && [ "$(sed -n 2p "$1")" = s3cret ]
EOF
chmod +x auth.sh

ip netns add "$ns"
ip link add vpnlab0 type veth peer name vpnlab1
ip link set vpnlab1 netns "$ns"
ip addr add 172.31.251.1/30 dev vpnlab0
ip link set vpnlab0 up
ip netns exec "$ns" ip addr add 172.31.251.2/30 dev vpnlab1
ip netns exec "$ns" ip link set vpnlab1 up
ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip addr add 10.99.0.1/32 dev lo
ip netns exec "$ns" ip addr add 203.0.113.10/32 dev lo

cat >server.conf <<EOF
dev tun
proto udp
port 1194
topology subnet
server 10.8.0.0 255.255.255.0
ca $dir/ca.crt
cert $dir/server.crt
key $dir/server.key
dh none
push "route 10.99.0.0 255.255.0.0"
push "dhcp-option DNS 10.8.0.1"
push "dhcp-option DOMAIN corp.test"
push "redirect-gateway def1"
push "block-outside-dns"
script-security 2
auth-user-pass-verify $dir/auth.sh via-file
verb 3
EOF
ip netns exec "$ns" openvpn --config server.conf --daemon --log "$dir/server.log" --writepid "$dir/openvpn.pid"
sleep 1

printf '10.99.0.1 intranet.corp.test\n203.0.113.10 public.corp.test\n' >hosts.corp
ip netns exec "$ns" dnsmasq --no-resolv --no-hosts --addn-hosts="$dir/hosts.corp" --local=/corp.test/ --user=root \
	--listen-address=10.8.0.1 --bind-dynamic --pid-file="$dir/dnsmasq.pid"
mkdir -p www
echo corp-ok >www/index.html
ip netns exec "$ns" python3 -m http.server 80 --directory www >http.log 2>&1 &
echo $! >http.pid

{
	echo "client"
	echo "dev tun"
	echo "proto udp"
	echo "remote 172.31.251.2 1194"
	echo "nobind"
	echo "remote-cert-tls server"
	echo "auth-user-pass"
	echo "<ca>"; cat ca.crt; echo "</ca>"
	echo "<cert>"; cat client.crt; echo "</cert>"
	echo "<key>"; cat client.key; echo "</key>"
} >client.ovpn
echo "стенд поднят: $dir/client.ovpn"
