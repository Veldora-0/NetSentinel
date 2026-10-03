"""NetSentinel Flask Backend Application.

Main entry point for the NetSentinel REST API and real-time Socket.IO connection server.
"""

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from config import Config
from database import init_db

def create_app(config_class=Config) -> tuple[Flask, SocketIO]:
    """Application factory for NetSentinel Flask Backend."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable Cross-Origin Resource Sharing
    CORS(app, resources={r"/api/*": {"origins": "*"}, r"/socket.io/*": {"origins": "*"}})

    # Initialize Database
    init_db(app)

    # Initialize Flask-SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # Register API Routes
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint to verify backend operational status."""
        return jsonify({
            "status": "ok",
            "service": "NetSentinel Backend"
        }), 200

    # Socket.IO Event Handlers
    @socketio.on("connect")
    def handle_connect():
        """Handle client Socket.IO connection."""
        emit("connection_response", {"status": "connected", "message": "Connected to NetSentinel Socket.IO Server"})

    @socketio.on("disconnect")
    def handle_disconnect():
        """Handle client Socket.IO disconnection."""
        pass

    @socketio.on("ping_server")
    def handle_ping(data):
        """Handle optional client ping test."""
        emit("pong_client", {"response": "pong", "received": data})

    return app, socketio


app, socketio = create_app()

if __name__ == "__main__":
    config = Config()
    print(f"Starting NetSentinel Backend Server on {config.HOST}:{config.PORT}...")
    socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG)
