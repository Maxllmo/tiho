#!/usr/bin/env python3
"""Create one client profile on an existing AmneziaWG Docker server. Never print keys."""
import argparse
import base64
import datetime
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import secrets

CONFIG_PATH = "/opt/amnezia/awg/awg0.conf"
AWG_FIELDS = [
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
]


def valid_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def parse_config(text):
    interface, peers, current = {}, [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(";"):
            continue
        if line.lower() == "[interface]":
            current = interface
        elif line.lower() == "[peer]":
            current = {}
            peers.append(current)
        elif line.startswith("["):
            raise ValueError("Неизвестная секция в конфигурации сервера.")
        else:
            key, separator, value = line.partition("=")
            if not separator or current is None:
                raise ValueError("Некорректный формат конфигурации сервера.")
            key, value = key.strip().lower(), value.strip()
            if key in {"allowedips", "address"} and key in current:
                current[key] += "," + value
            else:
                current[key] = value
    if not interface:
        raise ValueError("В конфигурации сервера нет [Interface].")
    return interface, peers


def choose_address(interface, peers, runtime_allowed):
    addresses = [ipaddress.ip_interface(s.strip()) for s in interface.get("address", "").split(",") if s.strip()]
    server = next((a for a in addresses if a.version == 4), None)
    if server is None or server.network.prefixlen < 16 or server.network.prefixlen > 30:
        raise ValueError("Нужна IPv4-подсеть сервера от /16 до /30. Настройки сервера не изменены.")
    used = []
    for peer in peers:
        for value in peer.get("allowedips", "").split(","):
            if value.strip():
                used.append(ipaddress.ip_network(value.strip(), strict=False))
    for line in runtime_allowed.splitlines():
        fields = line.split(None, 1)
        if len(fields) < 2:
            continue
        for value in re.split(r"[\s,]+", fields[1]):
            if value and value != "(none)":
                used.append(ipaddress.ip_network(value, strict=False))
    for candidate in server.network.hosts():
        if candidate == server.ip:
            continue
        if all(candidate.version != network.version or candidate not in network for network in used):
            return str(candidate) + "/32"
    raise ValueError("В подсети сервера нет свободных адресов. Настройки не изменены.")


def render_client(interface, address, endpoint, private_key, server_public, psk):
    if not all(valid_key(k) for k in [private_key, server_public, psk]):
        raise ValueError("Ядро вернуло некорректные ключи. Настройки не изменены.")
    port = int(interface.get("listenport", "0"))
    if not 0 < port <= 65535:
        raise ValueError("В конфигурации сервера не найден ListenPort.")
    host = endpoint.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        host = "[" + str(ip) + "]" if ip.version == 6 else str(ip)
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
            raise ValueError("Укажите IP или имя сервера без протокола и порта.")
    lines = ["[Interface]", "PrivateKey = " + private_key, "Address = " + address, "DNS = 1.1.1.1"]
    if "mtu" in interface:
        lines.append("MTU = " + interface["mtu"])
    for field in AWG_FIELDS:
        value = interface.get(field.lower(), "")
        if value:
            lines.append(field + " = " + value)
    lines += ["", "[Peer]", "PublicKey = " + server_public, "PresharedKey = " + psk,
              "Endpoint = " + host + ":" + str(port), "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


class Docker:
    def __init__(self, container):
        self.container = container

    @classmethod
    def discover(cls):
        result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            raise RuntimeError("Не удалось получить список контейнеров. Проверьте Docker на сервере.")
        names = [name for name in result.stdout.splitlines() if re.fullmatch(r"amnezia-awg[\w.-]*", name)]
        if len(names) != 1:
            raise RuntimeError("Не найден единственный работающий контейнер AmneziaWG. Укажите его через --container ИМЯ.")
        return cls(names[0])

    def run(self, arguments, input_text=None):
        command = ["docker", "exec"] + (["-i"] if input_text is not None else []) + [self.container] + arguments
        try:
            result = subprocess.run(command, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Контейнер AmneziaWG не ответил за 30 секунд. Повторите команду.") from None
        if result.returncode:
            # CLI errors can contain configuration data. Do not echo stdout/stderr or key arguments.
            raise RuntimeError("Команда в контейнере не выполнена. Проверьте имя контейнера и наличие интерфейса awg0.")
        return result.stdout.strip()

    def read_config(self):
        return self.run(["cat", CONFIG_PATH]) + "\n"

    def public_key(self):
        return self.run(["awg", "show", "awg0", "public-key"])

    def allowed_ips(self):
        return self.run(["awg", "show", "awg0", "allowed-ips"])

    def client_public_key(self, private):
        return self.run(["awg", "pubkey"], private + "\n")

    def keys(self):
        private = self.run(["awg", "genkey"])
        public = self.client_public_key(private)
        psk = self.run(["awg", "genpsk"])
        return private, public, psk

    def write_config(self, text):
        self.run(["sh", "-c", 'umask 077; cat > "$1.tiho-tmp" && chmod 600 "$1.tiho-tmp" && mv "$1.tiho-tmp" "$1"', "sh", CONFIG_PATH], text)

    def add_peer(self, public, psk, address):
        self.run(["awg", "set", "awg0", "peer", public, "preshared-key", "/dev/stdin", "allowed-ips", address], psk + "\n")

    def remove_peer(self, public):
        self.run(["awg", "set", "awg0", "peer", public, "remove"])


def secure_write(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def existing_client(api, output, interface, server_public, endpoint, peers, runtime):
    client_interface, client_peers = parse_config(output.read_text(encoding="utf-8-sig"))
    if len(client_peers) != 1:
        raise ValueError("Сохранённый профиль повреждён. Выберите другое имя устройства.")
    peer = client_peers[0]
    private, psk = client_interface.get("privatekey", ""), peer.get("presharedkey", "")
    if not valid_key(private) or not valid_key(psk) or peer.get("publickey") != server_public:
        raise ValueError("Сохранённый профиль не соответствует серверу. Выберите другое имя устройства.")
    address = client_interface.get("address", "")
    try:
        ip = ipaddress.ip_interface(address)
        if ip.version != 4 or ip.network.prefixlen != 32:
            raise ValueError()
    except ValueError:
        raise ValueError("В сохранённом профиле некорректный адрес. Выберите другое имя устройства.") from None
    public = api.client_public_key(private)
    persisted = any(p.get("publickey") == public and p.get("presharedkey") == psk
                    and p.get("allowedips") == address for p in peers)
    active = any(line.split(None, 1) == [public, address] for line in runtime.splitlines())
    expected = render_client(interface, address, endpoint, private, server_public, psk)
    if not valid_key(public) or not persisted or not active or output.read_text(encoding="utf-8-sig") != expected:
        raise ValueError("Профиль или параметры сервера изменились. Выберите другое имя устройства; старые клиенты не изменены.")
    output.chmod(0o600)
    return output


def create_client(api, endpoint, name, directory, check=False, reuse=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name):
        raise ValueError("Имя устройства: 1–40 латинских букв, цифр, дефисов или подчёркиваний.")
    original = api.read_config()
    interface, peers = parse_config(original)
    runtime = api.allowed_ips()
    server_public = api.public_key()
    if not valid_key(server_public):
        raise ValueError("Не удалось получить публичный ключ сервера.")
    directory = Path(directory)
    output = directory / (name + ".conf")
    if not check and output.exists():
        if reuse:
            return existing_client(api, output, interface, server_public, endpoint, peers, runtime)
        raise ValueError("Файл уже существует: " + str(output) + ". Скопируйте его или выберите другое имя устройства.")
    address = choose_address(interface, peers, runtime)
    if check:
        render_client(interface, address, endpoint, server_public, server_public, server_public)
        return address
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    private, public, psk = api.keys()
    if not valid_key(public):
        raise ValueError("Не удалось создать публичный ключ клиента.")
    client = render_client(interface, address, endpoint, private, server_public, psk)
    temporary = directory / (name + ".conf." + secrets.token_hex(8) + ".tmp")
    secure_write(temporary, client)
    backups = directory / "backups"
    backups.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup = backups / (name + "-server-" + stamp + ".conf")
    changed = False
    try:
        secure_write(backup, original)
        if api.read_config() != original:
            raise RuntimeError("Конфигурация сервера изменилась во время подготовки. Повторите команду.")
        server = original.rstrip() + "\n\n# Tiho: " + name + "\n[Peer]\nPublicKey = " + public + "\nPresharedKey = " + psk + "\nAllowedIPs = " + address + "\n"
        changed = True
        api.write_config(server)
        api.add_peer(public, psk, address)
        if public not in api.allowed_ips():
            raise RuntimeError("Не удалось проверить добавление устройства.")
        temporary.replace(output)
        return output
    except Exception:
        if changed:
            try:
                api.write_config(original)
                api.remove_peer(public)
            except Exception:
                raise RuntimeError("Ошибка добавления и отката. Резервная копия сервера: " + str(backup)) from None
        raise
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Создать отдельный клиентский .conf на существующем сервере AmneziaWG.")
    parser.add_argument("--endpoint", required=True, help="Публичный IP или имя сервера, без порта")
    parser.add_argument("--name", default="Tiho-PC")
    parser.add_argument("--container", help="Имя контейнера; по умолчанию определяется автоматически")
    parser.add_argument("--reuse", action="store_true", help="Повторно получить существующий профиль после проверки его актуальности")
    parser.add_argument("--check", action="store_true", help="Только проверить сервер, ничего не менять")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Запустите команду на сервере от root или через sudo.\n")
    try:
        descriptor = os.open("/run/lock/tiho-create-client.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            api = Docker(args.container) if args.container else Docker.discover()
            result = create_client(api, args.endpoint, args.name, Path("/root/tiho-clients"), args.check, args.reuse)
        print("Проверка пройдена. Свободный адрес: " + result if args.check else "Конфигурация создана: " + str(result))
        if not args.check:
            print("VPN не перезапускался. Скопируйте только этот клиентский .conf на свой ПК. Ключи в чат не отправляйте.")
    except subprocess.TimeoutExpired:
        parser.exit(1, "Docker не ответил за 30 секунд. Повторите команду.\n")
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(1, "Ошибка: " + str(error) + "\n")


if __name__ == "__main__":
    main()
