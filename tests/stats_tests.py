import unittest

import mock

import events.stats


class StatsTests(unittest.TestCase):
    def test_no_address(self):
        client = events.stats.StatsClient()
        client.count("test")
        self.assertIsNone(client.sock)

    @mock.patch("socket.socket")
    def test_send_message(self, mock_socket):
        mock_socket_object = mock.MagicMock()
        mock_socket.return_value = mock_socket_object
        client = events.stats.StatsClient()

        client.connect("1.2.3.4", 1234)
        client.count("test")
        mock_socket_object.sendto.assert_called_with(
            "eventcollector.test:1|c\n", ("1.2.3.4", 1234))


class MakeStatsClientTests(unittest.TestCase):
    def test_make_empty_client(self):
        client = events.stats.make_stats_client({})
        self.assertIsNone(client.sock)

    def test_make_client(self):
        config = {"stats.address": "1.2.3.4:1234"}
        client = events.stats.make_stats_client(config)
        self.assertIsNotNone(client.sock)
        self.assertEqual(client.address, ("1.2.3.4", 1234))

    def test_default_port(self):
        config = {"stats.address": "1.2.3.4"}
        client = events.stats.make_stats_client(config)
        self.assertIsNotNone(client.sock)
        self.assertEqual(client.address, ("1.2.3.4", 8125))
