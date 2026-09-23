#!/usr/bin/env python3

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from metranova.processors.clickhouse.flow_stitching import FlowStitchingProcessor, anonymize_ip


def make_slice(**overrides):
    """A minimal, already-normalized `data_flow`-schema row, as PMAcctFlowProcessor.build_message
    would return it. start_time/end_time are ms-since-epoch ints, matching that code."""
    row = {
        "start_time": 1_700_000_000_000,
        "end_time": 1_700_000_060_000,  # 60s slice
        "collector_id": "test-collector",
        "policy_originator": "unknown",
        "policy_level": "tlp:amber",
        "policy_scope": [],
        "ext": "{}",
        "flow_type": "netflow",
        "device_id": "router1",
        "device_ref": None,
        "src_as_id": 100,
        "src_as_ref": None,
        "src_ip": "192.0.2.10",
        "src_ip_ref": None,
        "src_port": 443,
        "dst_as_id": 200,
        "dst_as_ref": None,
        "dst_ip": "198.51.100.20",
        "dst_ip_ref": None,
        "dst_port": 51000,
        "protocol": "tcp",
        "in_interface_id": "eth0",
        "in_interface_ref": None,
        "in_interface_edge": True,
        "out_interface_id": "eth1",
        "out_interface_ref": None,
        "out_interface_edge": False,
        "peer_as_id": None,
        "peer_as_ref": None,
        "peer_ip": None,
        "peer_ip_ref": None,
        "ip_version": 4,
        "application_port": 443,
        "bit_count": 8000,
        "packet_count": 10,
    }
    row.update(overrides)
    return row


class TestAnonymizeIp(unittest.TestCase):
    def test_ipv4_truncated_to_prefix(self):
        # ipv4_prefix=117 -> 117-96=21 bits kept -> a /21
        result = anonymize_ip("192.0.2.10", 4, ipv4_prefix=117, ipv6_prefix=48)
        self.assertEqual(result, "192.0.0.0")

    def test_ipv4_multicast_preserved(self):
        result = anonymize_ip("224.0.0.5", 4, ipv4_prefix=117, ipv6_prefix=48)
        self.assertEqual(result, "224.0.0.5")

    def test_ipv6_truncated_to_prefix(self):
        result = anonymize_ip("2001:db8:1234:5678::1", 6, ipv4_prefix=117, ipv6_prefix=48)
        self.assertEqual(result, "2001:db8:1234::")

    def test_ipv6_multicast_preserved(self):
        result = anonymize_ip("ff02::1", 6, ipv4_prefix=117, ipv6_prefix=48)
        self.assertEqual(result, "ff02::1")

    def test_ipv6_6to4_preserved(self):
        result = anonymize_ip("2002:c000:204::1", 6, ipv4_prefix=117, ipv6_prefix=48)
        self.assertEqual(result, "2002:c000:204::1")

    def test_none_passthrough(self):
        self.assertIsNone(anonymize_ip(None, 4, 117, 48))

    def test_empty_string_passthrough(self):
        self.assertEqual(anonymize_ip("", 4, 117, 48), "")

    def test_unparseable_left_unmodified(self):
        self.assertEqual(anonymize_ip("not-an-ip", 4, 117, 48), "not-an-ip")


class TestFlowStitchingProcessor(unittest.TestCase):
    def setUp(self):
        self.mock_pipeline = MagicMock()
        # These tests exercise the stitching behavior itself, which is only live when the
        # feature is enabled -- CLICKHOUSE_FLOW_STITCH_ENABLED is off by default (see
        # TestFlowStitchingEnabledFlag for the off-by-default / gating behavior).
        # Avoid any real PMAcctFlowProcessor construction concerns (cachers, env vars) --
        # its own logic is covered by test_pmacct.py. We only test the stitching layer here.
        with patch.dict(os.environ, {"CLICKHOUSE_FLOW_STITCH_ENABLED": "true"}), \
             patch("metranova.processors.clickhouse.flow_stitching.PMAcctFlowProcessor") as MockInner:
            self.mock_inner = MockInner.return_value
            self.processor = FlowStitchingProcessor(self.mock_pipeline)
        # Stop the real background sweep thread from racing with the test; we call
        # _sweep_once() directly wherever we want to trigger a sweep.
        self.processor.sweep_interval = 10_000  # effectively never fires on its own during tests

    def test_table_defaults(self):
        self.assertEqual(self.processor.table, "data_flow_anonymized")
        self.assertEqual(self.processor.table_engine, "MergeTree")
        self.assertEqual(self.processor.table_engine_opts, "")

    def test_create_table_command_has_expected_columns(self):
        cmd = self.processor.create_table_command()
        self.assertIn("CREATE TABLE IF NOT EXISTS data_flow_anonymized", cmd)
        self.assertIn("ENGINE = MergeTree()", cmd)
        self.assertIn("`start_time` DateTime64(3, 'UTC')", cmd)
        self.assertIn("`end_time` DateTime64(3, 'UTC')", cmd)
        self.assertIn("`duration` Float64", cmd)
        self.assertIn("`flow_count` UInt64", cmd)
        self.assertIn("`bit_count` UInt64", cmd)
        self.assertIn("`packet_count` UInt64", cmd)
        # no *_ip_ref passthrough columns -- this is the anonymized table, like data_flow_anonymized_5m
        self.assertNotIn("src_ip_ref", cmd)

    def test_build_message_absorbs_and_never_emits(self):
        self.mock_inner.build_message.return_value = [make_slice()]
        result = self.processor.build_message({"raw": "msg"}, {})
        self.assertEqual(result, [])
        # but it should have been accumulated internally
        self.assertEqual(len(self.processor._flows), 1)

    def test_build_message_handles_no_slices(self):
        self.mock_inner.build_message.return_value = None
        result = self.processor.build_message({"raw": "msg"}, {})
        self.assertEqual(result, [])
        self.assertEqual(len(self.processor._flows), 0)

    def test_stitching_combines_slices_of_same_flow(self):
        slice1 = make_slice(start_time=1_700_000_000_000, end_time=1_700_000_060_000, bit_count=8000, packet_count=10)
        slice2 = make_slice(start_time=1_700_000_060_000, end_time=1_700_000_120_000, bit_count=16000, packet_count=20)
        self.mock_inner.build_message.side_effect = [[slice1], [slice2]]

        self.processor.build_message({"raw": "msg1"}, {})
        self.processor.build_message({"raw": "msg2"}, {})

        self.assertEqual(len(self.processor._flows), 1)
        entry = next(iter(self.processor._flows.values()))
        self.assertEqual(entry["start_time"], 1_700_000_000_000)
        self.assertEqual(entry["end_time"], 1_700_000_120_000)
        self.assertEqual(entry["bit_count"], 24000)
        self.assertEqual(entry["packet_count"], 30)
        self.assertEqual(entry["stitched_flows"], 2)

    def test_different_fingerprints_stay_separate(self):
        slice_a = make_slice(src_port=443)
        slice_b = make_slice(src_port=8443)
        self.mock_inner.build_message.side_effect = [[slice_a], [slice_b]]

        self.processor.build_message({"raw": "a"}, {})
        self.processor.build_message({"raw": "b"}, {})

        self.assertEqual(len(self.processor._flows), 2)

    def test_sweep_flushes_after_inactivity_and_anonymizes(self):
        self.processor.inactivity_timeout = 0.01
        self.processor.max_flow_timeout = 86400
        slice1 = make_slice()
        self.mock_inner.build_message.return_value = [slice1]
        self.processor.build_message({"raw": "msg"}, {})

        time.sleep(0.05)
        completed = self.processor._sweep_once()

        self.assertEqual(len(completed), 1)
        self.assertEqual(len(self.processor._flows), 0)  # flushed entry removed
        row = completed[0]
        self.assertEqual(row["duration"], 60.0)
        self.assertEqual(row["bit_count"], 8000)
        self.assertEqual(row["packet_count"], 10)
        self.assertEqual(row["flow_count"], 1)
        # src_ip 192.0.2.10 anonymized to a /21 (default ipv4_prefix=117 -> 21 bits)
        self.assertEqual(row["src_ip"], "192.0.0.0")

    def test_sweep_flushes_long_flow_even_without_inactivity(self):
        self.processor.inactivity_timeout = 86400  # long, shouldn't trigger
        self.processor.max_flow_timeout = 100  # seconds of *event* time
        slice1 = make_slice(start_time=1_700_000_000_000, end_time=1_700_000_000_000 + 200_000)  # 200s span
        self.mock_inner.build_message.return_value = [slice1]
        self.processor.build_message({"raw": "msg"}, {})

        completed = self.processor._sweep_once()  # no sleep needed -- event-time span already exceeds max
        self.assertEqual(len(completed), 1)

    def test_sweep_does_not_flush_active_flow(self):
        self.processor.inactivity_timeout = 86400
        self.processor.max_flow_timeout = 86400
        slice1 = make_slice()
        self.mock_inner.build_message.return_value = [slice1]
        self.processor.build_message({"raw": "msg"}, {})

        completed = self.processor._sweep_once()
        self.assertEqual(completed, [])
        self.assertEqual(len(self.processor._flows), 1)

    def test_write_rows_uses_stored_client(self):
        client = MagicMock()
        self.processor.set_clickhouse_client(client)
        row = self.processor._finalize({
            "template": make_slice(),
            "start_time": 1_700_000_000_000,
            "end_time": 1_700_000_060_000,
            "bit_count": 8000,
            "packet_count": 10,
            "stitched_flows": 1,
        })
        self.processor._write_rows([row])
        self.assertTrue(client.insert.called)
        _, kwargs = client.insert.call_args
        self.assertEqual(kwargs["table"], "data_flow_anonymized")

    def test_write_rows_without_client_does_not_raise(self):
        row = self.processor._finalize({
            "template": make_slice(),
            "start_time": 1_700_000_000_000,
            "end_time": 1_700_000_060_000,
            "bit_count": 8000,
            "packet_count": 10,
            "stitched_flows": 1,
        })
        # _client is None until set_clickhouse_client() is called -- should log and return, not raise
        self.processor._write_rows([row])



class TestFlowStitchingEnabledFlag(unittest.TestCase):
    """CLICKHOUSE_FLOW_STITCH_ENABLED is the single on/off switch, and it is off by
    default -- simply adding this processor to a pipeline YAML must not silently start
    a new table or a background thread until someone opts in."""

    def _make_processor(self, env_value=None):
        env = dict(os.environ)
        if env_value is None:
            env.pop("CLICKHOUSE_FLOW_STITCH_ENABLED", None)
        else:
            env["CLICKHOUSE_FLOW_STITCH_ENABLED"] = env_value
        with patch.dict(os.environ, env, clear=True), \
             patch("metranova.processors.clickhouse.flow_stitching.PMAcctFlowProcessor") as MockInner:
            mock_inner = MockInner.return_value
            processor = FlowStitchingProcessor(MagicMock())
        return processor, mock_inner

    def test_disabled_by_default(self):
        processor, _ = self._make_processor(env_value=None)
        self.assertFalse(processor.enabled)
        self.assertIsNone(processor._sweep_thread)
        self.assertFalse(processor.match_message({"raw": "msg"}))
        self.assertIsNone(processor.create_table_command())

    def test_disabled_build_message_absorbs_nothing(self):
        processor, mock_inner = self._make_processor(env_value=None)
        mock_inner.build_message.return_value = [make_slice()]
        result = processor.build_message({"raw": "msg"}, {})
        self.assertEqual(result, [])
        self.assertEqual(len(processor._flows), 0)

    def test_enabled_via_env_var(self):
        processor, _ = self._make_processor(env_value="true")
        self.assertTrue(processor.enabled)
        self.assertIsNotNone(processor._sweep_thread)
        self.assertTrue(processor._sweep_thread.is_alive())
        self.assertTrue(processor.match_message({"raw": "msg"}))
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS data_flow_anonymized",
            processor.create_table_command(),
        )

    def test_enabled_accepts_common_truthy_strings(self):
        for value in ("1", "yes", "YES", "True"):
            processor, _ = self._make_processor(env_value=value)
            self.assertTrue(processor.enabled, f"expected enabled for {value!r}")


if __name__ == "__main__":
    unittest.main()
