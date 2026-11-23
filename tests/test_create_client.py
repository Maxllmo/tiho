import base64
import ipaddress
from pathlib import Path
import runpy
import stat
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

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
    def client_public_key(self, private): return key(7)
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

    def test_retry_reuses_verified_profile_without_new_peer(self):
        api = FakeDocker()
        with tempfile.TemporaryDirectory() as directory:
            output = helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory)
            original = output.read_bytes()
            mutations, peers = api.mutations, dict(api.peers)
            self.assertEqual(helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory, reuse=True), output)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(api.mutations, mutations)
            self.assertEqual(api.peers, peers)

    def test_retry_rejects_stale_or_removed_profile_without_changes(self):
        for change in ["endpoint", "runtime", "server", "config"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                api = FakeDocker()
                output = helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory)
                if change == "runtime": api.peers.pop(key(7))
                if change == "server": api.config = api.config.replace("S1 = 16", "S1 = 17")
                if change == "config": output.write_text(output.read_text().replace("PresharedKey = " + key(8), "PresharedKey = " + key(9)))
                before, mutations, peers = output.read_bytes(), api.mutations, dict(api.peers)
                endpoint = "198.51.100.11" if change == "endpoint" else "198.51.100.10"
                with self.assertRaises(ValueError):
                    helper["create_client"](api, endpoint, "Tiho-PC", directory, reuse=True)
                self.assertEqual(output.read_bytes(), before)
                self.assertEqual(api.mutations, mutations)
                self.assertEqual(api.peers, peers)

    def test_old_partial_file_does_not_block_new_attempt(self):
        api = FakeDocker()
        with tempfile.TemporaryDirectory() as directory:
            stale = Path(directory) / "Tiho-PC.conf.tmp"
            stale.write_text("old interrupted download")
            output = helper["create_client"](api, "198.51.100.10", "Tiho-PC", directory)
            self.assertTrue(output.exists())
            self.assertEqual(stale.read_text(), "old interrupted download")
            self.assertEqual(list(Path(directory).glob("Tiho-PC.conf.*.tmp")), [])

    def test_container_discovery_supports_both_amnezia_generations(self):
        for name in ["amnezia-awg", "amnezia-awg2"]:
            with mock.patch.object(helper["subprocess"], "run", return_value=SimpleNamespace(returncode=0, stdout="squid\n" + name + "\n")):
                self.assertEqual(helper["Docker"].discover().container, name)
        for names in ["squid\n", "amnezia-awg\namnezia-awg2\n"]:
            with mock.patch.object(helper["subprocess"], "run", return_value=SimpleNamespace(returncode=0, stdout=names)):
                with self.assertRaisesRegex(RuntimeError, "--container"):
                    helper["Docker"].discover()

    def test_docker_timeout_does_not_expose_keys(self):
        with mock.patch.object(helper["subprocess"], "run", side_effect=helper["subprocess"].TimeoutExpired(["secret-key"], 30)):
            with self.assertRaisesRegex(RuntimeError, "30 секунд") as caught:
                helper["Docker"]("amnezia-awg2").add_peer("secret-key", "secret-psk", "10.8.1.3/32")
            self.assertNotIn("secret", str(caught.exception))

    def test_address_allocator_respects_overlapping_ranges(self):
        iface, peers = helper["parse_config"](SERVER)
        peers[0]["allowedips"] = "10.8.1.0/25"
        self.assertEqual(helper["choose_address"](iface, peers, ""), "10.8.1.128/32")

    def test_public_key_slashes_are_not_parsed_as_ip_prefixes(self):
        iface, peers = helper["parse_config"](SERVER)
        self.assertEqual(helper["choose_address"](iface, peers, "abc/12publickey\t10.8.1.2/32"), "10.8.1.3/32")


if __name__ == "__main__": unittest.main()
