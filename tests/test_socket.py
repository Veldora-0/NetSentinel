"""Unit test for Socket.IO server connection."""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app


def test_socketio_connect():
    """Test Flask-SocketIO client connection and event handling."""
    app, socketio = create_app()
    socket_client = socketio.test_client(app)

    assert socket_client.is_connected()

    received = socket_client.get_received()
    assert len(received) > 0
    assert received[0]["name"] == "connection_response"
    assert received[0]["args"][0]["status"] == "connected"

    # Ping test
    socket_client.emit("ping_server", {"test": "ping"})
    received_ping = socket_client.get_received()
    assert len(received_ping) > 0
    assert received_ping[0]["name"] == "pong_client"
    assert received_ping[0]["args"][0]["response"] == "pong"

    socket_client.disconnect()
