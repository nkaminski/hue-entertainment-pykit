"""Manage DTLS connections with Philips Hue Bridges using pre-shared keys."""

from contextlib import suppress
import logging
import select
import socket
import threading
import time

from OpenSSL._util import ffi as _ffi, lib as _lib
from OpenSSL.SSL import Connection, Context, DTLS_CLIENT_METHOD, Error, WantReadError

from ..exceptions.dtls_handshake_exception import DTLSHandshakeException
from ..models.bridge import Bridge

logger = logging.getLogger(__name__)

_DEFAULT_UDP_PORT = 2100
_DEFAULT_SOCK_TIMEOUT = 5
_DEFAULT_CIPHERS = ("PSK-AES256-GCM-SHA384",)
_PSK_CALLBACK_CDEF = (
    "unsigned int (*)(SSL *, const char *, char *, unsigned int, "
    "unsigned char *, unsigned int)"
)


class Dtls:
    """Manage DTLS connections and PSK handshakes with a Philips Hue Bridge."""

    def __init__(self, bridge: Bridge) -> None:
        """Initialize the DTLS manager from bridge connection details."""
        self._udp_port: int = _DEFAULT_UDP_PORT
        self._server_address: tuple[str, int] = (
            bridge.get_ip_address(),
            self._udp_port,
        )
        self._psk_key: bytes = bytes.fromhex(bridge.get_client_key())
        self._psk_identity: str = bridge.get_hue_application_id()
        self._ciphers: list[str] = list(_DEFAULT_CIPHERS)
        self._dtls_socket: Connection | None = None
        self._sock_timeout: int = _DEFAULT_SOCK_TIMEOUT
        self._psk_callback = None

    def __str__(self) -> str:
        """Return a string representation of the DTLS configuration."""
        return (
            "DTLS {\n"
            f"   server_address: {self._server_address},\n"
            f"   psk_key: {self._psk_key},\n"
            f"   psk_identity: {self._psk_identity},\n"
            f"   ciphers: {self._ciphers}\n"
            "}"
        )

    def get_server_address(self) -> tuple[str, int]:
        """Return the target bridge address and UDP port."""
        return self._server_address

    def get_socket(self) -> Connection | None:
        """Return the active DTLS socket, creating one if needed."""
        if self._dtls_socket is None:
            self._create_dtls_socket()
        return self._dtls_socket

    def _create_psk_callback(self):
        """Create the OpenSSL CFFI callback for Pre-Shared Key authentication."""
        psk_identity = self._psk_identity.encode("utf-8")
        psk_key = self._psk_key

        @_ffi.callback(_PSK_CALLBACK_CDEF)
        def _callback(_ssl, _hint, identity, max_identity_len, psk, max_psk_len):
            # pylint: disable=too-many-positional-arguments
            if (
                b"\x00" in psk_identity
                or len(psk_identity) + 1 > max_identity_len
                or len(psk_key) > max_psk_len
            ):
                return 0
            _ffi.memmove(identity, psk_identity, len(psk_identity))
            identity[len(psk_identity)] = b"\x00"
            _ffi.memmove(psk, psk_key, len(psk_key))
            return len(psk_key)

        return _callback

    def _create_dtls_socket(self) -> None:
        """Create a DTLS socket and OpenSSL context if not already initialized."""
        if self._dtls_socket is not None:
            return

        logger.info("Creating DTLS socket and context")
        context = Context(DTLS_CLIENT_METHOD)
        context.set_cipher_list(":".join(self._ciphers).encode("utf-8"))
        self._psk_callback = self._create_psk_callback()
        # pylint: disable=protected-access
        _lib.SSL_CTX_set_psk_client_callback(context._context, self._psk_callback)

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(self._sock_timeout)
        udp_socket.connect(self._server_address)

        self._dtls_socket = self.PatchedTLSWrappedSocket(context, udp_socket)
        self._dtls_socket.set_connect_state()

    def do_handshake(self) -> None:
        """Perform the DTLS handshake, closing the socket on failure."""
        self._create_dtls_socket()
        logger.info("Starting DTLS handshake")
        try:
            self._dtls_socket.do_handshake()
        except DTLSHandshakeException:
            self.close_socket()
            raise
        logger.info("DTLS handshake established")

    def close_socket(self) -> None:
        """Close the active DTLS socket and release callback references."""
        if self._dtls_socket is None:
            return
        self._dtls_socket.close()
        self._dtls_socket = None
        self._psk_callback = None

    # pylint: disable=abstract-method
    class PatchedTLSWrappedSocket(Connection):
        """OpenSSL DTLS Connection with handshake retry and thread-safe I/O."""

        _HANDSHAKE_TIMEOUT = 5.0
        _MAX_HANDSHAKE_RETRIES = 3

        def __init__(self, *args, **kwargs) -> None:
            """Initialize the wrapped DTLS connection."""
            super().__init__(*args, **kwargs)
            self._handshake_retries = 0
            self._send_lock = threading.Lock()

        def do_handshake(self) -> None:
            """Perform the DTLS handshake with retransmission and deadline bounds."""
            self._handshake_retries = 0
            # Enforce an overall wall-clock deadline because select.select() only
            # increments _handshake_retries when the socket times out waiting for
            # data. If stray packets, repeated HelloVerifyRequests, or ICMP errors
            # keep the socket readable without completing the handshake, the loop
            # would otherwise spin indefinitely.
            deadline = (
                time.monotonic()
                + self._HANDSHAKE_TIMEOUT * self._MAX_HANDSHAKE_RETRIES
            )

            while True:
                try:
                    super().do_handshake()
                    return
                except WantReadError as exc:
                    if (remaining := deadline - time.monotonic()) <= 0:
                        raise DTLSHandshakeException(
                            "DTLS handshake timed out"
                        ) from exc

                    timeout = self.DTLSv1_get_timeout()
                    wait_time = min(
                        1.0 if timeout is None else max(0.0, timeout),
                        remaining,
                    )
                    ready, _, _ = select.select([self._socket], [], [], wait_time)
                    if ready:
                        continue

                    self._handshake_retries += 1
                    logger.debug("Retransmission attempt: %s", self._handshake_retries)
                    if self._handshake_retries > self._MAX_HANDSHAKE_RETRIES:
                        raise DTLSHandshakeException(
                            "Maximum handshake retries exceeded"
                        ) from exc
                    self.DTLSv1_handle_timeout()
                except Error as exc:
                    raise DTLSHandshakeException(
                        f"DTLS handshake failed: {exc}"
                    ) from exc

        def send(self, buf: bytes, flags: int = 0) -> int:
            """Send data over DTLS and map OpenSSL errors to OSError."""
            with self._send_lock:
                try:
                    return super().send(buf, flags)
                except Error as exc:
                    raise OSError(f"DTLS send failed: {exc}") from exc

        def close(self) -> None:
            """Shut down the DTLS session and close the underlying UDP socket."""
            with self._send_lock:
                if self._socket is None:
                    return
                with suppress(Error):
                    self.shutdown()
                self._socket.close()
