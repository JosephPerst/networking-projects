import socket

class Client:

    def __init__(self, server_host='localhost', server_port=8080):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # create UDP socket
        self.server_host = server_host
        self.server_port = server_port
        self.recv_size = 2048 # number of bytes to receive from socket (frame size)
        self.client_socket.connect((self.server_host, self.server_port)) # associate socket to the destination (server)

    def send_message(self):
        message = input('Input lowercase sentence: ') # obtain a message from the user
        message_bytes = message.encode() # convert the message into bytes

        self.client_socket.send(message_bytes) # send the message (bytes) to the server

    def receive_modified_message(self):
        # self.client_socket.settimeout(2)
        # try:
            modified_message_bytes = self.client_socket.recv(self.recv_size) # receive a message over the socket (from the server)
            modified_message = modified_message_bytes.decode()
            print(f'Message from Server: {modified_message}')
        # except socket.timeout:
            # print("Timeout occurred prior to receiving message from the server.")

    def close_socket(self):
        self.client_socket.close()

    def run_client(self):
        self.send_message()
        self.receive_modified_message()
        self.close_socket()

if __name__ == '__main__':
    test_client = Client()
    test_client.run_client()
