"""
Contains the StreamingService class for managing the streaming of color data to Philips Hue lights.
This class is responsible for the DTLS connection setup and maintenance, and facilitates color data
transmission to lights in a Philips Hue Entertainment setup.
"""

from collections.abc import Mapping
import logging
import queue
import struct
import threading
from socket import error as SocketError

from ..models.payload import Payload
from ..models.entertainment_configuration import (
    EntertainmentConfiguration,
)
from ..bridge.entertainment_configuration_repository import (
    EntertainmentConfigurationRepository,
)
from ..network.dtls import Dtls
from ..utils.converter import Converter


logger = logging.getLogger(__name__)

RGBColor = tuple[int, int, int]
XYBColor = tuple[float, float, float]
ColorTuple = RGBColor | XYBColor
StreamInput = (
    tuple[int, int, int, int]
    | tuple[float, float, float, int]
    | Mapping[int, ColorTuple]
)


# pylint: disable=too-many-instance-attributes
class StreamingService:
    """
    Manages streaming color data to Philips Hue lights via a DTLS connection.

    This service handles the setup and maintenance of DTLS connections and transmits color information to lights.
    It includes methods for starting/stopping the stream, setting the color space, and processing color input.

    Attributes:
        _KEEP_ALIVE_INTERVAL (float): Interval for sending keep-alive messages.
        _DEFAULT_CHANNEL_VALUE (bytes): Default value for initializing streaming messages.
    """

    _KEEP_ALIVE_INTERVAL = 9.5
    _DEFAULT_CHANNEL_VALUE = struct.pack(">B", 0x00)
    _COLOR_SPACE = ["rgb", "xyb"]

    def __init__(
        self,
        entertainment_configuration: EntertainmentConfiguration,
        entertainment_configuration_repository: EntertainmentConfigurationRepository,
        dtls_service: Dtls,
    ):
        """
        Initializes the StreamingService with the necessary configuration and services.

        Args:
            entertainment_configuration (EntertainmentConfiguration): Configuration for the entertainment setup.
            entertainment_configuration_repository (EntertainmentConfigurationRepository): Repository for
            managing entertainment configurations.
            dtls_service (Dtls): Service for managing DTLS (Datagram Transport Layer Security) connections.
        """

        self._entertainment_config = entertainment_configuration
        self._entertainment_configuration_repository = (
            entertainment_configuration_repository
        )
        self._dtls_service = dtls_service

        self._protocol_name = "HueStream".encode("utf-8")
        self._version = struct.pack(">BB", 0x02, 0x00)
        self._sequence_id = struct.pack(">B", 0x07)
        self._reserved = b"\x00\x00"
        self._color_space = self._DEFAULT_CHANNEL_VALUE
        self._reserved2 = b"\x00"
        self._entertainment_id = self._entertainment_config.id.encode("utf-8")

        self._channel_data = b""
        self._last_message = self._init_message()
        self._is_connection_alive = False
        self._stop_event = threading.Event()

        self._input_queue = queue.Queue()
        self._connection_thread = threading.Thread(
            target=self._keep_connection_alive, daemon=True
        )
        self._processing_thread = threading.Thread(
            target=self._watch_user_input, daemon=True
        )

        self._reconnect_attempts = 0
        self._reconnect_lock = threading.Lock()

    def is_stream_active(self) -> bool:
        """Check if the streaming service is currently active.

        Returns:
            bool: True if the stream is active, False otherwise.
        """

        return self._is_connection_alive

    def set_color_space(self, value: str):
        """Set the color space for the streaming service.

        Args:
            value (str): The color space value to set ('rgb' or 'xyb').

        Raises:
            ValueError: If an invalid color space is provided.
        """

        if value.lower() in self._COLOR_SPACE:
            self._color_space = struct.pack(">B", 0x00 if value == "rgb" else 0x01)
        else:
            raise ValueError(f"Invalid color space '{value}'. Use 'rgb' or 'xyb'.")

    def start_stream(self):
        """Starts the streaming service.

        This method initiates the streaming process by setting up the DTLS connection and
        starting the threads responsible for keeping the connection alive and monitoring user input.
        It also notifies the entertainment configuration repository to start the streaming session.
        """

        payload = (
            Payload()
            .set_key_and_or_value("id", self._entertainment_config.id)
            .set_key_and_or_value("action", "start")
        )
        self._entertainment_configuration_repository.put_configuration(payload)
        self._dtls_service.do_handshake()
        self._stop_event.clear()
        self._is_connection_alive = True

        if self._connection_thread.ident is not None:
            self._connection_thread = threading.Thread(
                target=self._keep_connection_alive, daemon=True
            )
        if self._processing_thread.ident is not None:
            self._processing_thread = threading.Thread(
                target=self._watch_user_input, daemon=True
            )

        self._connection_thread.start()
        self._processing_thread.start()

    def stop_stream(self):
        """Stops the streaming service, ensuring that all resources are properly released.

        This method stops the streaming process by terminating the connection threads and closing the DTLS socket.
        It also updates the entertainment configuration repository to indicate that the streaming session has stopped.
        """

        if self._dtls_service.get_socket() and self._is_connection_alive:
            self._is_connection_alive = False
            self._stop_event.set()

            self._connection_thread.join(timeout=10)
            self._processing_thread.join(timeout=10)

            if self._connection_thread.is_alive() or self._processing_thread.is_alive():
                logger.warning("One or more threads did not terminate as expected.")

            self._dtls_service.close_socket()

            payload = (
                Payload()
                .set_key_and_or_value("id", self._entertainment_config.id)
                .set_key_and_or_value("action", "stop")
            )
            self._entertainment_configuration_repository.put_configuration(payload)
        else:
            raise SocketError(
                "Unable to stop stream: DTLS socket is not available or stream is not active."
            )

    def turn_off_lights(self) -> None:
        """Turn off all light services in the entertainment configuration."""
        for light in self._entertainment_config.light_services:
            self._entertainment_configuration_repository.turn_off_light(light.rid)

    def set_input(self, user_input: StreamInput):
        """Queue a single-channel 4-tuple or channel-to-color mapping for streaming."""
        if isinstance(user_input, Mapping):
            if user_input and all(
                isinstance(ch_id, int)
                and len(color) == 3
                and (self._is_valid_rgb8(color) or self._is_valid_xyb(color))
                for ch_id, color in user_input.items()
            ):
                self._input_queue.put(dict(user_input))
                return
        elif len(user_input) == 4 and (
            self._is_valid_rgb8(user_input[:3]) or self._is_valid_xyb(user_input[:3])
        ):
            self._input_queue.put(user_input)
            return

        logger.error(
            "Invalid input: values must be a valid rgb8 (0 - 255) or xyb (0.0 - 1.0)"
        )

    def _build_message(self, channel_data):
        """Constructs a message for streaming with the given channel data.

        Args:
            channel_data (bytes): The channel data to be included in the message. It includes various parameters such as
            protocol name, version, sequence ID, reserved bytes, color space, and entertainment ID, concatenated with
            the actual channel data.

        Returns:
            bytes: The constructed message, ready to be sent over the network.
        """

        return (
            self._protocol_name
            + self._version
            + self._sequence_id
            + self._reserved
            + self._color_space
            + self._reserved2
            + self._entertainment_id
            + channel_data
        )

    def _init_message(self) -> bytes:
        """Initialize the streaming message with default channel data.

        Returns:
            bytes: The initialized message.
        """

        x, y, b = Converter.xyb_to_rgb16((0.0, 0.0, 0.0))

        self._channel_data = self._DEFAULT_CHANNEL_VALUE
        self._channel_data += struct.pack(">HHH", x, y, b)

        return self._build_message(self._channel_data)

    def _keep_connection_alive(self):
        """Keeps the DTLS connection alive by sending messages at regular intervals.

        This method runs in a separate thread and is responsible for maintaining the DTLS connection.
        It periodically sends the last known message to keep the connection active.
        If the connection is lost, it attempts to reconnect.
        """

        while self._is_connection_alive:
            try:
                self._dtls_service.get_socket().send(self._last_message)
            except SocketError as e:
                logger.error("Connection lost: %s", e)
                if self._is_connection_alive:
                    logger.info("Attempting to reconnect...")
                    self._attempt_reconnect()
            self._stop_event.wait(self._KEEP_ALIVE_INTERVAL)

    def _watch_user_input(self):
        """Monitors and processes user input in a separate thread while the stream is active.

        This method continuously checks for user input in the input queue.
        If input is found, it processes the input according to the specified color space and
        sends the corresponding data to the light.
        """

        while self._is_connection_alive:
            try:
                user_input = self._input_queue.get(
                    timeout=0.1
                )  # using timeout to avoid busy waiting
                self._process_user_input(user_input)
            except queue.Empty:
                continue
            except ValueError as e:
                logger.error("Error in user input: %s", e)

    def _attempt_reconnect(self):
        """Attempts to reconnect the DTLS service with a limit of 3 attempts.

        This method tries to re-establish the DTLS connection up to three times in case of connection loss.
        It resets the reconnection attempt counter after a successful reconnection.
        """

        with self._reconnect_lock:
            if self._reconnect_attempts >= 3:
                logger.error(
                    "Maximum reconnection attempts reached. Unable to reconnect."
                )
                return

            try:
                self._dtls_service.close_socket()
                self._dtls_service.do_handshake()
                self._reconnect_attempts = 0
                logger.info("Reconnected to the DTLS service.")
            except OSError as e:
                self._reconnect_attempts += 1
                logger.error(
                    "Failed to reconnect attempt %s due to network error: %s",
                    self._reconnect_attempts,
                    e,
                )
            except Exception as e:  # pylint: disable=broad-except
                self._reconnect_attempts += 1
                logger.error(
                    "Failed to reconnect attempt %s due to unexpected error: %s",
                    self._reconnect_attempts,
                    e,
                )

    def _process_user_input(self, user_input):
        """Process a single-channel 4-tuple or channel-to-color mapping."""
        items = (
            [(*color, ch_id) for ch_id, color in user_input.items()]
            if isinstance(user_input, Mapping)
            else [user_input]
        )
        if not items or any(len(item) != 4 for item in items):
            raise ValueError(f"{user_input} invalid input. Expected 4 values.")

        packed_channels = []
        for rx, gy, bb, light_id in items:
            color = (rx, gy, bb)
            if not (self._is_valid_rgb8(color) or self._is_valid_xyb(color)):
                raise ValueError(
                    "Invalid input. Neither inputs are rgb8 or xyb compatible."
                )
            packed_channels.append(self._pack_color_data(color, light_id))

        self._send_channel_payload(b"".join(packed_channels))

    def _send_color_to_light(self, color: ColorTuple, value: int):
        """Send single-channel color data to a light over DTLS."""
        self._send_channel_payload(self._pack_color_data(color, value))

    def _send_channel_payload(self, channel_data: bytes) -> None:
        """Build and transmit a HueStream frame containing packed channel data."""
        try:
            self._channel_data = channel_data
            message = self._build_message(self._channel_data)
            logger.debug(message)
            self._dtls_service.get_socket().send(message)
            self._last_message = message
        except SocketError as e:
            logger.error("Error sending message: %s", e)
            if self._is_connection_alive:
                logger.info("Attempting to reconnect...")
                self._attempt_reconnect()

    def _pack_color_data(self, color: ColorTuple, value: int) -> bytes:
        """Packs the given color data into bytes for transmission.

        Args:
            color (Union[tuple[int, int, int], tuple[float, float, float]]): The color data in either
            RGB8 or XYB format.
            value (int): An integer value associated with the color data, such as the light's ID or channel number.

        Returns:
            bytes: The packed color data in byte format, ready for transmission.
        """

        channel_data = b""
        channel_data += struct.pack(">B", value)
        if self._is_valid_xyb(color):
            rx, gy, bb = Converter.xyb_to_rgb16(color)
        else:
            rx, gy, bb = Converter.rgb8_to_rgb16(color)

        logger.debug("Converted values: %s, %s, %s", rx, gy, bb)
        return channel_data + struct.pack(">HHH", rx, gy, bb)

    @classmethod
    def _is_valid_rgb8(cls, rgb8: tuple[int, int, int]) -> bool:
        """Check if the given RGB8 color is valid.

        Args:
            rgb8 (tuple[int, int, int]): A tuple representing the RGB8 color.

        Returns:
            bool: True if the color is a valid RGB8, False otherwise.
        """

        return all(0 <= value <= 255 for value in rgb8)

    @classmethod
    def _is_valid_xyb(cls, xyb: tuple[float, float, float]) -> bool:
        """Check if the given XYB color is valid.

        Args:
            xyb (tuple[float, float, float]): A tuple representing the XYB color.

        Returns:
            bool: True if the color is a valid XYB, False otherwise.
        """

        return all(0.0 <= value <= 1.0 for value in xyb)
