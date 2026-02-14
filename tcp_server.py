import socket
import json
import time
from pdu import HTTPDatagram, IPHeader
from pathlib import Path
from datetime import datetime

# for encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 32-byte key for AES-256
SHARED_KEY = b'ilovecy350somuchireallylovedoing'  # Exactly 32 bytes


class Server:
    """
    Represents a custom HTTP-like server using raw sockets. It handles connection requests,
    processes HTTP GET requests, and sends segmented responses using a Go-Back-N protocol.

    Attributes:
        server_ip (str): The server's IP address.
        gateway (str): The server's gateway IP address.
        server_port (int): The server's listening port.
        frame_size (int): Maximum frame size for transmitting data.
        window_size (int): Window size for the Go-Back-N protocol.
        timeout (int): Timeout for the server's socket operations.
        resources (dict): Dictionary containing available resources and metadata.
        base (int): Base sequence number for Go-Back-N protocol.
        seq_num (int): Current sequence number.
        ack_num (int): Current acknowledgment number.
    """

    def __init__(self, server_ip='127.128.0.1', gateway='127.128.0.254', server_port=8080, frame_size=1024, timeout=20):
        """
        Initializes the server with IP address, gateway, port, and network settings.

        Args:
            server_ip (str): Server's IP address.
            gateway (str): Server's gateway IP.
            server_port (int): Port on which the server listens.
            frame_size (int): Maximum size of each frame (default: 1024 bytes).
            window_size (int): Window size for Go-Back-N (default: 4).
            timeout (int): Timeout for socket operations (default: 5 seconds).
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.gateway = gateway

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.server_socket.bind((self.server_ip, 0))
        print(f"[Server] Listening on {self.server_ip}")


        self.frame_size = frame_size # Must match the frame_size of the client
        self.window_size = 4 # Must match the window_size of the client
        self.timeout = timeout
        self.base = 0
        self.seq_num = 0
        self.ack_num = 0

        # Load server resources from a JSON file
        base_path = Path(__file__).parent
        resources_path = base_path / 'resources.json'
        with open(resources_path, 'r') as f:
            self.resources = json.load(f)

    def accept_handshake(self):
        """
        Handles the three-way handshake for establishing a connection with a client.

        Returns:
            bool: True if the handshake is successful, False otherwise.
        """
        syn = False
        while not syn:
            frame = self.server_socket.recv(self.frame_size)
            datagram_fields = HTTPDatagram.from_bytes(frame)
            # debugging to ignore the spam of SYN requests
            if datagram_fields.flags != 2:
                print(f"[Server] Ignoring non-SYN frame during handshake: flags={datagram_fields.flags}")
                continue


            print(f"[Server] Waiting for new SYN, got frame with flags={HTTPDatagram.from_bytes(frame).flags}")

            ip_hdr = IPHeader.from_bytes(frame)
            print(f"[Server] Frame received with dst IP {ip_hdr.ip_daddr}")
            if ip_hdr.ip_daddr != '224.0.0.5':
                print(f"[DEBUG] Not multicast. IP dst={ip_hdr.ip_daddr}")
                datagram_fields = HTTPDatagram.from_bytes(frame)
                print(f"[DEBUG] Flags={datagram_fields.flags}, Next hop={datagram_fields.next_hop}, Seq={datagram_fields.seq_num}")

            if IPHeader.from_bytes(frame).ip_daddr != '224.0.0.5':
                datagram_fields = HTTPDatagram.from_bytes(frame)

                if datagram_fields.flags == 2 and datagram_fields.next_hop == self.server_ip:
                    syn = True
                    self.ack_num = datagram_fields.seq_num + 1

                    # Extract window size from client SYN
                    self.window_size = datagram_fields.window_size
                    print("[Server] SYN received, preparing SYN/ACK")
                    print(f"[Server] Window size negotiated: {self.window_size}")
            
            


        # Step 2: Send SYN/ACK
        self.server_socket.settimeout(self.timeout)
        syn_ack_datagram = HTTPDatagram(
            ip_saddr=self.server_ip, ip_daddr=datagram_fields.ip_saddr,
            source_port=self.server_port, dest_port=datagram_fields.source_port,
            seq_num=self.seq_num, ack_num=self.ack_num, flags=18, window_size=self.window_size,
            next_hop=self.gateway, data='SYN-ACK'
        )
        self.server_socket.sendto(syn_ack_datagram.to_bytes(), (self.gateway, 0))
        self.seq_num += 1

        # Step 3: Receive ACK
        ack = False
        while not ack:
            try:
                frame = self.server_socket.recv(self.frame_size)
            except socket.timeout:
                self.reset_connection()
                return False
            
            if IPHeader.from_bytes(frame).ip_daddr != '224.0.0.5':
                datagram_fields = HTTPDatagram.from_bytes(frame)
                print(f"[Server] Waiting for ACK: SEQ {self.seq_num}")
                print(f"[Server] Received frame flags={datagram_fields.flags}, ack={datagram_fields.ack_num}")

                if datagram_fields.flags == 16 and datagram_fields.ack_num == self.seq_num and datagram_fields.next_hop == self.server_ip:
                    ack = True
                    print("[Server] Handshake complete")
                    return True
        return False

    def receive_request_segments(self):
        """
        Receives the segmented request from the client, reassembling it into a full request.

        Returns:
            tuple: The reassembled request string, the source port, and the source IP address.
        """

        self.server_socket.settimeout(0.25)
        request = ''
        content_length = None

        while True:
            try:
                frame_bytes = self.server_socket.recv(self.frame_size)
                frame = IPHeader.from_bytes(frame_bytes)
                if frame.ip_daddr == self.server_ip:
                    datagram = HTTPDatagram.from_bytes(frame_bytes)
                    if (datagram.next_hop == self.server_ip and
                        datagram.dest_port == self.server_port and
                        datagram.flags == 24 and
                        datagram.seq_num == self.ack_num):

                        self.ack_num += 1
                        if isinstance(datagram.data, bytes):
                            request += datagram.data.decode(errors='ignore')  # or use 'replace' to show placeholders for bad bytes
                        else:
                            request += datagram.data


                        # Send ACK immediately
                        ack = HTTPDatagram(
                            ip_saddr=self.server_ip,
                            ip_daddr=datagram.ip_saddr,
                            source_port=self.server_port,
                            dest_port=datagram.source_port,
                            seq_num=self.seq_num,
                            ack_num=self.ack_num,
                            flags=16,
                            window_size=self.window_size,
                            next_hop=self.gateway,
                            data='ACK'
                        )
                        self.server_socket.sendto(ack.to_bytes(), (self.gateway, 0))

                        # If we now have headers, check for content length
                        if content_length is None and "\r\n\r\n" in request:
                            headers = request.split("\r\n\r\n")[0]
                            for line in headers.split("\r\n"):
                                if line.lower().startswith("content-length:"):
                                    content_length = int(line.split(":")[1].strip())

                            # If there's no content length, we're done
                            if content_length is None:
                                return request, datagram.source_port, datagram.ip_saddr

                        # If content length is known, check if body is fully received
                        if content_length is not None:
                            body = request.split("\r\n\r\n", 1)[1]
                            if len(body.encode()) >= content_length:
                                return request, datagram.source_port, datagram.ip_saddr

            except socket.timeout:
                continue


    def process_request(self, request, dest_port, dest_ip):
        """
        Processes the client's HTTP GET request and prepares the appropriate response.

        Args:
            request (str): The client's HTTP request.
            dest_port (int): The client's source port.
            dest_ip (str): The client's source IP address.
        """
        self.server_socket.settimeout(self.timeout)

        request_lines = request.split('\r\n')
        first_line = request_lines[0].split()
        method = first_line[0]
        resource = first_line[1]
        modified_since = None
        flags = 17 # Default flags for error response

        ### Determine the response message based on the HTTP Request.

        if method == "POST":
            content_index = request.find("\r\n\r\n") + 4
            post_body = request[content_index:]

            # Write the POST body to a file
            try:
                with open("post_received.txt", "w", encoding="utf-8") as f:
                    f.write(post_body.strip())
                print("[Server] POST request received and saved to 'post_received.txt'")
            except Exception as e:
                print("[Server] Failed to write POST body to file:", e)

            # still store in memory (depricated and used in the beginning of coding)
            self.resources[resource] = {
                "last_modified": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                "file_size": len(post_body),
                "etag": "wowigenerastedataglmao123",
                "data": post_body
            }
            
            with open('resources.json', 'w', encoding='utf-8') as f:
                json.dump(self.resources, f, indent=4)

            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPOST request successfully received."
            flags = 24

        elif method == "GET":
            if resource not in self.resources:
                response = "HTTP/1.1 404 Not Found\r\n\r\nResource Not Found"
            else:
                # Check for If-Modified-Since header line
                for line in request_lines[1:]:
                    if line.startswith("If-Modified-Since:"):
                        modified_since = line.split(":", 1)[1].strip()
                        break
                resource_info = self.resources[resource]

                # If header line exists, compare dates to determine response type
                if modified_since:
                    modified_since_time = datetime.strptime(modified_since, "%a, %d %b %Y %H:%M:%S GMT")
                    last_modified_time = datetime.strptime(resource_info['last_modified'], "%a, %d %b %Y %H:%M:%S GMT")
                    if last_modified_time <= modified_since_time:
                        response = "HTTP/1.1 304 Not Modified\r\n\r\n"
                    else:
                        object = resource_info['data']
                        cleaned_data = object.encode('utf-8').decode('unicode_escape')
                        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(cleaned_data)}\r\n\r\n{cleaned_data}"
                        flags = 24
                else:
                    object = resource_info['data']
                    cleaned_data = object.encode('utf-8').decode('unicode_escape')
                    response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(cleaned_data)}\r\n\r\n{cleaned_data}"
                    flags = 24

        else:
            response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request"

                
                
        ### Segment the response (segments no larger than frame_size)
        aesgcm = AESGCM(SHARED_KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, response.encode(), None)
        response_bytes = nonce + ciphertext  # Prefix nonce so client can extract it

        # MASSIVEEE Debug strings
        print("[DEBUG] Full plaintext response length:", len(response.encode()))
        print("[DEBUG] Encrypted payload (with nonce):", len(response_bytes))
        max_data_length = self.frame_size - 60
        print("[DEBUG] Frame size:", self.frame_size)
        print("[DEBUG] Max data per segment:", max_data_length)
        response_data_segments = [response_bytes[i:i + max_data_length] for i in range(0, len(response_bytes), max_data_length)]
        print("[DEBUG] Total segments to send:", len(response_data_segments))
        #checking the encrypted payload
        print("[Server] Encrypted payload (nonce + ciphertext):", response_bytes)


        max_data_length = self.frame_size - 60
        response_data_segments = [response_bytes[i:i + max_data_length] for i in range(0, len(response_bytes), max_data_length)]
        
        ### Send the response segments using Go-Back-N
        self.base = self.seq_num
        offset = self.seq_num

        while self.base < len(response_data_segments) + offset:
            start = self.base - offset
            end = start + self.window_size

            for i in range(start, min(end, len(response_data_segments))):
                segment = response_data_segments[i]
                is_last = (i == len(response_data_segments) - 1)

                # Determine appropriate flags
                if is_last:
                    segment_flags = 25 if flags != 17 else 17  # FIN or error FIN
                else:
                    segment_flags = 24

                print(f"[Server] Sending segment {i + 1}/{len(response_data_segments)}, flags={segment_flags}")

                datagram = HTTPDatagram(
                    ip_saddr=self.server_ip,
                    ip_daddr=dest_ip,
                    source_port=self.server_port,
                    dest_port=dest_port,
                    seq_num=self.seq_num,
                    ack_num=self.ack_num,
                    flags=segment_flags,
                    window_size=self.window_size,
                    next_hop=self.gateway,
                    data=segment
                )

                self.server_socket.sendto(datagram.to_bytes(), (self.gateway, 0))
                self.seq_num += 1
            
            # Process acknowledgements
            try:
                current_time = time.time()
                ack_rec = False
                while time.time() - current_time < self.timeout:
                    ack_bytes = self.server_socket.recv(self.frame_size)
                    ack = HTTPDatagram.from_bytes(ack_bytes)
                    print(f"[Server] Received ACK:")
                    print(f"    From: {ack.ip_saddr}:{ack.source_port}")
                    print(f"    To:   {ack.ip_daddr}:{ack.dest_port}")
                    print(f"    Data: {ack.data}")
                    print(f"    Flags: {ack.flags}, Seq: {ack.seq_num}, Ack: {ack.ack_num}")
                    print(f"    Next Hop: {ack.next_hop}")
                    print(f"    Expected from IP: {dest_ip}, Expected ACK flag: 16")

                    if ack.next_hop == self.server_ip:
                        print("[Server] ACK next_hop is valid")
                    else:
                        print("[Server] ACK next_hop is invalid")

                    if ack.ip_saddr == dest_ip:
                        print("[Server] ACK source IP is correct")
                    else:
                        print("[Server] ACK source IP is incorrect")

                    if ack.flags == 16:
                        print("[Server] ACK flag is correct")
                    else:
                        print("[Server] ACK flag is not correct")

                    # Main condition
                    if ack.next_hop == self.server_ip and ack.ip_saddr == dest_ip and ack.flags == 16:
                        self.base = ack.ack_num
                        self.seq_num = self.base
                        ack_rec = True
                        print(f"[Server] ACK accepted. New base: {self.base}, seq_num updated to: {self.seq_num}")
                        break

                if not ack_rec:
                    self.seq_num = self.base

            except socket.timeout:
                self.seq_num = self.base # Align sequence number back to base (first unacknowledged packet)
            
            print("[Server] Finished sending response.")

                
    def reset_connection(self):
        """
        Resets the server's connection state (sequence numbers, base, and acknowledgment).
        """
        self.base = 0
        self.seq_num = 0
        self.ack_num = 0
        self.server_socket.settimeout(None)

    def close_server(self):
        """
        Closes the server's raw socket.
        """
        self.server_socket.close()

    def run_server(self, request_list=None):
        """
        Runs the server, accepting handshake, receiving requests, and processing responses.

        Args:
            request_list (list, optional): List to append incoming requests (used for debugging).
        """
        while True:
            connected = self.accept_handshake()
            if connected:
                request, port, ip = self.receive_request_segments()
                print("[Server] Received request:")
                print(request)
                if request_list is not None:
                    request_list.append(request)

                print("[Server] Finished processing previous request, awaiting new connection...")

                self.process_request(request, port, ip)
            else:
                print("[Server] Handshake failed.")
            self.reset_connection()


if __name__ == "__main__":
    server = Server(frame_size=128, gateway = '127.0.0.1')
    server.run_server()


'''
    Loop indefinitely:
    For each interface and its socket:
        Try to receive a frame:
            If frame is received:
                Extract source and destination MAC addresses.
                If source MAC is not in MAC table:
                    Record source MAC with interface and current timestamp.
                If destination MAC is known:
                    Forward frame to corresponding interface.
                Else:
                    Flood the frame to all other interfaces.
        If error is EAGAIN or EWOULDBLOCK:
            Ignore it
        Else if any other exception:
            Print error and continue down code
    Wait briefly before next cycle of this
'''