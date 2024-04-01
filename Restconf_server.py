from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "admin": "password"
}

class RESTCONF:
    def __init__(self, switch_instance):
        self.switch = switch_instance
        self.init_routes()

    # Verify user credentials
    @auth.verify_password
    def verify_password(username, password):
        if username in users and users[username] == password:
            return username

    def init_routes(self):
        @app.route('/ports', methods=['GET'])
        @auth.login_required
        def get_ports_status():
            return jsonify(self.switch.mac_addresses)

        @app.route('/<port>', methods=['GET'])
        @auth.login_required
        def get_port_status(port):
            if port == 'port1':
                return jsonify(self.switch.mac_addresses['port1'])
            elif port == 'port2':
                return jsonify(self.switch.mac_addresses['port2'])
            else:
                return jsonify({"error": "Invalid port specified"}), 400

        @app.route('/timer', methods=['GET'])
        @auth.login_required
        def get_timer():
            return jsonify(self.switch.packet_timeout)\


        @app.route('/timer', methods=['PUT'])
        @auth.login_required
        def set_timer():
            data = request.json
            if 'timeout' in data:
                new_timeout = data['timeout']
                self.switch.packet_timeout = new_timeout
                return jsonify({"message": f"Packet timeout set to {new_timeout}"}), 200
            else:
                return jsonify({"error": "Timeout value not provided"}), 400

        @app.route('/switch/<port>', methods=['PUT'])
        @auth.login_required
        def configure_port(port):
            # Your implementation here
            return jsonify({"message": f"Configuration for port {port} updated successfully"}), 200