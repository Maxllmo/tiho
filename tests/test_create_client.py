import base64
import ipaddress
from pathlib import Path
import runpy
import stat
import tempfile
import unittest

helper = runpy.run_path(str(Path(__file__).resolve().parents[1] / "build/create-client.py"))
key = lambda value: base64.b64encode(bytes([value]) * 32).decode()
SERVER = f"""[Interface]
PrivateKey = {key(1)}
Address = 10.8.1.0/24
ListenPort = 43798
S1 = 16
S2 = 16
S3 = 16
S4 = 16
HeaderProtectionKey = {key(2)}
H1 = 1000-2000

[Peer]
PublicKey = {key(3)}
AllowedIPs = 10.8.1.1/32
"""


class FakeDocker:
    def __init__(self, fail=False):
        self.config = SERVER
        self.peers = {key(3): "10.8.1.1/32", key(4): "10.8.1.2/32"}
        self.fail = fail
        self.mutations = 0

    def read_config(self): return self.config
    def public_key(self): return key(5)
    def allowed_ips(self): return "\n".join(k + "\t" + v for k, v in self.peers.items())
    def keys(self): return key(6), key(7), key(8)
    def write_config(self, text): self.config = text; self.mutations += 1
    def add_peer(self, public, psk, address):
        if self.fail: raise RuntimeError("Simulated live-peer update failure")
        self.peers[public] = address
    def remove_peer(self, public): self.peers.pop(public, None)


class ClientCreationTests(unittest.TestCase):
    def test_check_does_not_change_server_or_write_files(self):
        api = FakeDocker()
        with tempfile.TemporaryDirectory() as directory:
            result = helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory, True)
            self.assertEqual(result, "10.8.1.3/32")
            self.assertEqual(api.mutations, 0)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_new_peer_preserves_existing_clients_and_obfuscation(self):
        api = FakeDocker()
        with tempfile.TemporaryDirectory() as directory:
            output = helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory)
            exported = output.read_text()
            self.assertIn("PrivateKey = " + key(6), exported)
            self.assertNotIn("PrivateKey = " + key(1), exported)
            self.assertIn("PublicKey = " + key(5), exported)
            self.assertIn("HeaderProtectionKey = " + key(2), exported)
            self.assertIn("H1 = 1000-2000", exported)
            self.assertIn("Endpoint = 198.51.100.10:43798", exported)
            self.assertEqual(api.peers[key(3)], "10.8.1.1/32")
            self.assertEqual(api.peers[key(4)], "10.8.1.2/32")
            self.assertEqual(api.peers[key(7)], "10.8.1.3/32")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(next((Path(directory) / "backups").glob("*.conf")).read_text(), SERVER)
            with self.assertRaises(ValueError): helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory)

    def test_failed_update_restores_server_and_removes_partial_export(self):
        api = FakeDocker(fail=True)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError): helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory)
            self.assertEqual(api.config, SERVER)
            self.assertEqual(len(api.peers), 2)
            self.assertFalse((Path(directory) / "Tiho-PC.conf").exists())
            self.assertFalse((Path(directory) / "Tiho-PC.conf.tmp").exists())

    def test_address_allocator_respects_overlapping_ranges(self):
        iface, peers = helper["parse_config"](SERVER)
        peers[0]["allowedips"] = "10.8.1.0/25"
        self.assertEqual(helper["choose_address"](iface, peers, ""), "10.8.1.128/32")

    def test_public_key_slashes_are_not_parsed_as_ip_prefixes(self):
        iface, peers = helper["parse_config"](SERVER)
        self.assertEqual(helper["choose_address"](iface, peers, "abc/12publickey\t10.8.1.2/32"), "10.8.1.3/32")


if __name__ == "__main__": unittest.main()
