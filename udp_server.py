import socket
import time

class Server:

    def __init__(self, server_port=8080):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # create UDP socket
        self.server_port = server_port
        self.recv_size = 2048
        self.server_socket.bind(('', self.server_port)) # Listen on port 

    def process_message(self):
        while True:
            message_bytes, client_address = self.server_socket.recvfrom(self.recv_size) # receive a message over the socket (from any client)
            # time.sleep(3)
            modified_message_bytes = message_bytes.decode().upper().encode() # make the message all uppercase
            self.server_socket.sendto(modified_message_bytes, client_address) # send the modified message over the socket (to any client)

if __name__ == '__main__':
    test_server = Server()
    test_server.process_message()
