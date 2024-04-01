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
                port_status_dict = self.switch.mac_addresses['port1'].copy()
                port_status = self.switch._port1_disabled
                port_status_dict["name"] = self.switch.switch_port1_name

            elif port == 'port2':
                port_status_dict = self.switch.mac_addresses['port2'].copy()
                port_status = self.switch._port2_disabled
                port_status_dict["name"] = self.switch.switch_port2_name

            else:
                return jsonify({"error": "Invalid port specified"}), 400

            if port_status == True:
                port_status_dict["status"] = "disabled"
            else:
                port_status_dict["status"] = "enabled"
            return jsonify(port_status_dict)

        @app.route('/<port>', methods=['PUT'])
        @auth.login_required
        def set_port_name(port):
            data = request.json
            if 'port_name' in data:
                new_port_name = data['port_name']
                if port == 'port1':
                    self.switch.switch_port1_name = new_port_name
                elif port == 'port2':
                    self.switch.switch_port2_name = new_port_name
                elif port == 'switch':
                    self.switch.switch_hostname = new_port_name
                else:
                    return jsonify({"error": "Invalid port specified"}), 400

                return jsonify({"message": f"New port name {new_port_name} set to {port}"}), 200

            elif 'disable' in data:
                status = data['disable']
                if port == 'port1':
                    self.switch._port1_disabled = status
                elif port == 'port2':
                    self.switch._port2_disabled = status
                elif port == 'switch':
                    self.switch._port1_disabled = status
                    self.switch._port2_disabled = status
                else:
                    return jsonify({"error": "Invalid port specified"}), 400
                return jsonify({"message": f"{port} status changed"}), 200
            else:
                return jsonify({"error": "Timeout value not provided"}), 400

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
                return jsonify({"error": "Timeout value not provided"}), 400\

        @app.route('/switch/<port>', methods=['PUT'])
        @auth.login_required
        def configure_port(port):
            # Your implementation here
            return jsonify({"message": f"Configuration for port {port} updated successfully"}), 200