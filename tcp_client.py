import socket
import random
import time
import threading
from datetime import datetime
from pdu import HTTPDatagram, IPHeader
import traceback #import to check errors
import subprocess #import for opening in firefox (VM)
import shutil

#bonus
import webbrowser
from pathlib import Path

# for encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 32-byte key for AES-256
SHARED_KEY = b'ilovecy350somuchireallylovedoing'  # Exactly 32 bytes


class Client:
    """
    Represents an HTTP client that communicates with a server using a custom protocol via raw sockets.
    
    Attributes:
        client_ip (str): The client's IP address.
        server_ip (str): The server's IP address.
        gateway (str): The gateway address for the client.
        client_port (int): The client's source port, randomly chosen during initialization.
        server_port (int): The server's destination port.
        frame_size (int): Maximum frame size for transmitting data.
        window_size (int): Window size for Go-Back-N protocol.
        timeout (int): Socket timeout for receiving data.
        base (int): Base sequence number for the Go-Back-N protocol.
        seq_num (int): Current sequence number.
        ack_num (int): Current acknowledgment number.
    """

    def __init__(self, client_ip='127.0.0.1', server_ip='127.128.0.1', gateway='127.0.0.254', server_port=8080, frame_size=1024, timeout=2):
        """
        Initializes the client with given IP addresses, ports, and network settings.

        Args:
            client_ip (str): Client's IP address.
            server_ip (str): Server's IP address.
            gateway (str): Client's gateway.
            server_port (int): Server's port (default: 8080).
            frame_size (int): Maximum frame size (default: 1024 bytes).
            window_size (int): Window size for Go-Back-N protocol (default: 5).
            timeout (int): Socket timeout (default: 11 seconds).
        """
        self.client_ip = client_ip
        self.client_port = random.randint(1024, 65535)  # Random client port
        self.server_ip = server_ip
        self.server_port = server_port
        self.gateway = gateway

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.client_socket.bind((self.client_ip, 0))
        self.client_socket.settimeout(timeout)

        self.frame_size = frame_size # Must match the frame_size of the server
        self.window_size = 4 # Must match the window_size of the server
        self.timeout = timeout

        self.base = 0
        self.seq_num = 0
        self.ack_num = 0

    def initiate_handshake(self):
        """
        Initiates a three-way handshake with the server to establish a connection.
        
        Returns:
            bool: True if the handshake is successful, False otherwise.
        """
        # Step 1: Send SYN
        syn_datagram = HTTPDatagram(
            ip_saddr=self.client_ip, ip_daddr=self.server_ip,
            source_port=self.client_port, dest_port=self.server_port,
            seq_num=self.seq_num, ack_num=self.ack_num,
            flags=2, window_size=self.window_size, next_hop=self.gateway, data='SYN'
        )
        self.client_socket.sendto(syn_datagram.to_bytes(), (self.gateway, 0))
        self.seq_num += 1
        print(f"[Client] >>> SYN SENT")
        print(f"[Client]   From {self.client_ip}:{self.client_port} → {self.server_ip}:{self.server_port}")
        print(f"[Client]   next_hop: {syn_datagram.next_hop}, flags: {syn_datagram.flags}, seq: {syn_datagram.seq_num}")



        # Step 2: Receive SYN/ACK
        syn_ack = False
        while not syn_ack:
            try:
                frame = self.client_socket.recv(self.frame_size)
            except socket.timeout:
                return False

            datagram_fields = HTTPDatagram.from_bytes(frame)
            if datagram_fields.flags == 18 and datagram_fields.next_hop == self.client_ip:
                syn_ack = True
                self.ack_num = datagram_fields.seq_num + 1

                # Update client-side window size based on server's advertised size
                self.window_size = datagram_fields.window_size
                print(f"[Client] Window size updated to: {self.window_size}")

                
                # Step 3: Send ACK
                ack_datagram = HTTPDatagram(
                    ip_saddr=self.client_ip, ip_daddr=self.server_ip,
                    source_port=self.client_port, dest_port=self.server_port,
                    seq_num=self.seq_num, ack_num=self.ack_num,
                    flags=16, window_size=self.window_size, next_hop=self.gateway, data='ACK'
                )
                self.client_socket.sendto(ack_datagram.to_bytes(), (self.gateway, 0))
                return True
        return False

    def build_request(self, resource, timestamp=None):
        """
        Builds an HTTP GET request string.

        Args:
            resource (str): The requested resource.
            timestamp (str, optional): If-Modified-Since timestamp.

        Returns:
            str: The HTTP request as a string.
        """
        request = f"GET {resource} HTTP/1.1\r\nHost: {self.server_ip}\r\n"
        if timestamp:
            request += f"If-Modified-Since: {timestamp}\r\n"
        request += "\r\n"
        return request
    
    def build_post_request(self, resource, data):
        """
        Builds an HTTP POST request string.

        Args:
            resource (str): The resource to post to.
            data (str): The data to be sent in the POST body.

        Returns:
            str: The POST request as a string.
        """
        request = f"POST {resource} HTTP/1.1\r\nHost: {self.server_ip}\r\nContent-Length: {len(data)}\r\n\r\n{data}"
        return request


    def send_request_segments(self, request):
        """
        Segments and sends the HTTP request using Go-Back-N protocol.

        Args:
            request (str): The full HTTP request string.
        """
        # Segment the request into chunks that fit within the frame size
        request_bytes = request.encode()
        max_data_length = self.frame_size - 60  # Allow space for the header
        request_data_segments = [request_bytes[i:i + max_data_length] for i in range(0, len(request_bytes), max_data_length)]

        flags = 24  # Set both ACK and PSH flags for request data

        self.base = self.seq_num  # Initialize base sequence number
        offset = self.seq_num  # Offset to track the sequence number for segments

        # Sending segments using Go-Back-N
        while self.base < len(request_data_segments) + offset:
            for segment in request_data_segments[self.base - offset:self.base - offset + self.window_size]:
                new_datagram = HTTPDatagram(
                    ip_saddr=self.client_ip, ip_daddr=self.server_ip,
                    source_port=self.client_port, dest_port=self.server_port,
                    seq_num=self.seq_num, ack_num=self.ack_num,
                    flags=flags, window_size=self.window_size, next_hop=self.gateway, data=segment.decode()
                )
                self.client_socket.sendto(new_datagram.to_bytes(), (self.gateway, 0))
                self.seq_num += 1
                
           
            # Process acknowledgements
            try:
                current_time = time.time()
                ack_rec = False
                while time.time() - current_time < self.timeout:
                    frame_bytes = self.client_socket.recv(self.frame_size)
                    datagram_fields = HTTPDatagram.from_bytes(frame_bytes)

                    if (datagram_fields.next_hop == self.client_ip and datagram_fields.ip_saddr == self.server_ip and datagram_fields.flags == 16 and datagram_fields.ack_num > self.base):
                        # Update the base sequence number after successful acknowledgement
                        self.base = datagram_fields.ack_num
                        self.seq_num = self.base
                        ack_rec = True
                        break
                if not ack_rec:
                    self.seq_num = self.base
            except socket.timeout:
                self.seq_num = self.base  # Timeout: reset sequence number to base (retry)
                
    def process_response_segments(self, requested_resource):
        """
        Receives and reassembles the response segments from the server.

        Returns:
            str: The full response as a string.
        """
        
        self.client_socket.settimeout(0.25)
        response = b''
        print("[DEBUG] Starting to collect response segments...")
        finished = False
        last_sender_ip = None
        last_sender_port = None
        seen_seq_nums = set()


        while not finished:
            current_time = time.time()

            while time.time() - current_time < 20 and not finished:
                try:
                    response_datagram_bytes = self.client_socket.recv(self.frame_size)
                    ip_header = IPHeader.from_bytes(response_datagram_bytes)

                    if ip_header.ip_daddr == self.client_ip:
                        datagram_fields = HTTPDatagram.from_bytes(response_datagram_bytes)

                        if (
                            datagram_fields.next_hop == self.client_ip and
                            datagram_fields.dest_port == self.client_port and
                            datagram_fields.flags in [17, 24, 25] and
                            datagram_fields.seq_num == self.ack_num and
                            datagram_fields.seq_num not in seen_seq_nums
                        ):
                            print(f"[Client] Received seq: {datagram_fields.seq_num}, expected ack: {self.ack_num}")

                            self.ack_num += 1
                            seen_seq_nums.add(datagram_fields.seq_num)
                            segment_data = datagram_fields.data
                            if isinstance(segment_data, str):
                                segment_data = segment_data.encode(errors='replace')  # don't corrupt the stream
                            response += segment_data 
                            print(f"[DEBUG] Total received segment bytes so far: {len(response)}") #more debugging LOLLL

                            
                            #debug and verify each segment
                            print(f"[Client] Appending segment data: seq_num={datagram_fields.seq_num}, segment_len={len(datagram_fields.data)}, total_so_far={len(response)}")

                            last_sender_ip = datagram_fields.ip_saddr
                            last_sender_port = datagram_fields.source_port

                            print(f"[Client] <<< Segment received:")
                            print(f"    From: {datagram_fields.ip_saddr}:{datagram_fields.source_port}")
                            print(f"    To:   {datagram_fields.ip_daddr}:{datagram_fields.dest_port}")
                            print(f"    Flags: {datagram_fields.flags}, Seq: {datagram_fields.seq_num}, Ack will be: {self.ack_num}")

                            # Send ACK for every valid segment received
                            ack = HTTPDatagram(
                                ip_saddr=self.client_ip,
                                ip_daddr=last_sender_ip,
                                source_port=self.client_port,
                                dest_port=last_sender_port,
                                seq_num=self.seq_num,
                                ack_num=self.ack_num,
                                flags=16,
                                window_size=self.window_size,
                                next_hop=self.gateway,
                                data='ACK'
                            )

                            print(f"[Client] >>> Sending ACK:")
                            print(f"    To: {last_sender_ip}:{last_sender_port}")
                            print(f"    Flags: 16, Seq: {self.seq_num}, Ack: {self.ack_num}")


                            self.client_socket.sendto(ack.to_bytes(), (self.gateway, 0))

                            if datagram_fields.flags in [17, 25]:  # FIN or RST
                                finished = True
                                #tells us whetehrt the client recieves the final segment of FIN
                                print(f"[Client] FIN received from {datagram_fields.ip_saddr}, marking transmission complete.")


                except socket.timeout:
                    continue
           # decrypt and return decryption     
        print(f"[Client] Finished receiving segments, attempting decryption")
        print("[Client] Total response length:", len(response))

        if not response:
            print("[Client] No response data collected. Exiting.")
            return ""

        if response:
            
            #checkin the encrypted responce
            print("[Client] Encrypted response bytes:", response)
            nonce = response[:12]  # First 12 bytes
            ciphertext = response[12:]
            aesgcm = AESGCM(SHARED_KEY)
            try:
                decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode()
                print("[Client] Decrypted response:", decrypted) #checkong the decrypted responce
            
                
                print("[DEBUG] Decrypted full response for browser logic:", decrypted)
                # Open browser for html
                if (
                    "HTTP/1.1 200 OK" in decrypted and
                    ("<html" in decrypted.lower() or "<!doctype html>" in decrypted.lower())
                ):
                    #Save decrypted HTML to /tmp
                    tmp_path = Path("/tmp/received_index.html")
                    html_body = decrypted.split("\r\n\r\n", 1)[-1]

                    with open(tmp_path, "w", encoding="utf-8") as f:
                        f.write(html_body)
                    os.chmod(tmp_path, 0o644)  # Make file readable

                    # Copy it to your home directory where Firefox (as user) can access it
                    home_path = Path.home() / "received_index.html"
                    shutil.copy(tmp_path, home_path)
                    os.chmod(home_path, 0o644)  # Also make copy readable

                    print(f"[Client] Saved decrypted HTML to {home_path}")

                    try:
                        subprocess.Popen(["firefox", str(home_path.resolve())], env={"DISPLAY": ":0"})
                        print(f"[Client] Opened in Firefox: {home_path.resolve()}")
                    except Exception as e:
                        print("[Client] Failed to open Firefox:", e)
                        print(f"[Client] Please open the file manually at: {home_path.resolve()}")
                else:
                    print("[Client] Response is not HTML. Skipping browser open.")

                
                return decrypted
            
            
            except Exception as e:
                print("[Client] Decryption failed:", e)
                traceback.print_exc()
                print("[Client] Raw decrypted bytes (if any):", decrypted if 'decrypted' in locals() else "N/A")
                return "Decryption failed"
        else:
            return ""


    def close_socket(self):
        """
        Closes the client's socket.
        """
        self.client_socket.close()

    def request_resource(self, resource, timestamp=None, method="GET", data=None):

        """
        Orchestrates the resource request process: handshake, request sending, and response processing.

        Args:
            resource (str): The requested resource.
            timestamp (str, optional): If-Modified-Since timestamp.

        Returns:
            str: The server's response.
        """
        response = ""
        connection = self.initiate_handshake()
        if connection:
            if method == "POST":
                request = self.build_post_request(resource, data)
            else:
                request = self.build_request(resource, timestamp)

            self.send_request_segments(request)
            response = self.process_response_segments(resource)

            if response is None:
                response = "No response received or decryption failed."

            print("[Server] Final response (plaintext before encrypt):")
            print(response)
        else:
            response = "Failed to connect to the server."

        self.close_socket()
        return response


if __name__ == "__main__":
    client = Client(frame_size=128, gateway='127.128.0.1')

    # Make the request to the server
    response = client.request_resource("/index.html", method="GET")
    
    # Print the response from the server
    print("\n[Final Response from Server]:")
    print(response)