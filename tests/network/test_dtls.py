"""Unit tests for the Dtls class."""

import unittest
from unittest.mock import MagicMock, patch

from OpenSSL.SSL import Error, WantReadError

from hue_entertainment_pykit.exceptions.dtls_handshake_exception import (
    DTLSHandshakeException,
)
from hue_entertainment_pykit.models.bridge import Bridge
from hue_entertainment_pykit.network.dtls import Dtls


# pylint: disable=protected-access, attribute-defined-outside-init
class TestDtls(unittest.TestCase):
    """Test suite for DTLS connection management with a Philips Hue Bridge."""

    def setUp(self) -> None:
        """Set up a mocked bridge, UDP socket, and Dtls instance."""
        self.mock_bridge = MagicMock(spec=Bridge)
        self.mock_bridge.get_ip_address.return_value = "192.168.1.2"
        self.mock_bridge.get_client_key.return_value = "0123456789abcdef"
        self.mock_bridge.get_hue_application_id.return_value = "test_app_id"

        self.mock_udp = MagicMock()
        self.mock_udp.fileno.return_value = 1
        socket_patcher = patch(
            "hue_entertainment_pykit.network.dtls.socket.socket",
            return_value=self.mock_udp,
        )
        self.mock_socket_cls = socket_patcher.start()
        self.addCleanup(socket_patcher.stop)

        self.dtls_service = Dtls(self.mock_bridge)

    def test_initialization(self) -> None:
        """Test that server address and PSK key are initialized from the bridge."""
        self.assertEqual(self.dtls_service._server_address[0], "192.168.1.2")
        self.assertIsInstance(self.dtls_service._psk_key, bytes)

    def test_get_server_address(self) -> None:
        """Test that get_server_address returns the bridge host and DTLS port."""
        self.assertEqual(
            self.dtls_service.get_server_address(), ("192.168.1.2", 2100)
        )

    def test_close_socket(self) -> None:
        """Test that close_socket closes the DTLS socket and clears its reference."""
        mock_tls_socket = MagicMock(spec=Dtls.PatchedTLSWrappedSocket)
        self.dtls_service._dtls_socket = mock_tls_socket
        self.dtls_service.close_socket()
        mock_tls_socket.close.assert_called_once()
        self.assertIsNone(self.dtls_service._dtls_socket)

    def test_get_socket_creates_socket(self) -> None:
        """Test that get_socket initializes a PatchedTLSWrappedSocket on first call."""
        dtls_sock = self.dtls_service.get_socket()
        self.assertIsInstance(dtls_sock, Dtls.PatchedTLSWrappedSocket)
        self.mock_udp.settimeout.assert_called_once_with(5)
        self.mock_udp.connect.assert_called_once_with(("192.168.1.2", 2100))

    @patch(
        "hue_entertainment_pykit.network.dtls.select.select",
        return_value=([], [], []),
    )
    @patch.object(
        Dtls.PatchedTLSWrappedSocket, "DTLSv1_get_timeout", return_value=0.01
    )
    @patch.object(
        Dtls.PatchedTLSWrappedSocket, "DTLSv1_handle_timeout", return_value=True
    )
    @patch("OpenSSL.SSL.Connection.do_handshake", side_effect=WantReadError())
    def test_do_handshake_max_retries_exceeded(
        self, _mock_hs, mock_handle_timeout, _mock_get_timeout, _mock_select
    ) -> None:
        """Test that do_handshake raises DTLSHandshakeException after 3 retries."""
        with self.assertRaises(DTLSHandshakeException):
            self.dtls_service.do_handshake()
        self.assertEqual(mock_handle_timeout.call_count, 3)
        self.assertIsNone(self.dtls_service._dtls_socket)

    @patch(
        "hue_entertainment_pykit.network.dtls.time.monotonic",
        side_effect=[0.0, 16.0],
    )
    @patch("OpenSSL.SSL.Connection.do_handshake", side_effect=WantReadError())
    def test_do_handshake_overall_deadline_exceeded(
        self, _mock_hs, _mock_monotonic
    ) -> None:
        """Test that do_handshake raises DTLSHandshakeException when deadline expires."""
        with self.assertRaises(DTLSHandshakeException):
            self.dtls_service.do_handshake()
        self.assertIsNone(self.dtls_service._dtls_socket)

    @patch("OpenSSL.SSL.Connection.send", side_effect=Error("SSL error"))
    def test_send_maps_openssl_error_to_oserror(self, _mock_send) -> None:
        """Test that PatchedTLSWrappedSocket.send maps OpenSSL Error to OSError."""
        dtls_sock = self.dtls_service.get_socket()
        with self.assertRaises(OSError):
            dtls_sock.send(b"HueStream")


if __name__ == "__main__":
    unittest.main()
