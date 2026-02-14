import socket
import threading
import time
import errno

class Switch:
    def __init__(self, interfaces):
        """
        Initialize a simple Layer 2 switch.
        
        Args:
            interfaces (dict): Mapping of port names to ip_saddr, ip_daddr
        """
        self.interfaces = interfaces
        self.mac_table = {}  # Maps MAC addresses
        self.interface_sockets = {}

        for name, (ip_saddr, _) in interfaces.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.bind((ip_saddr, 0))
            sock.setblocking(False)
            self.interface_sockets[name] = sock

    def learn_source(self, src_mac, interface):
        self.mac_table[src_mac] = (interface, time.time())

    def forward_frame(self, data, dst_mac, recv_iface):
        # Try to find the destination MAC in the table
        if dst_mac in self.mac_table:
            out_iface = self.mac_table[dst_mac][0]
            if out_iface != recv_iface:
                sock = self.interface_sockets[out_iface]
                dest_ip = self.interfaces[out_iface][1]
                sock.sendto(data, (dest_ip, 0))
                print(f"[Switch] Forwarding frame from {recv_iface} to {out_iface if dst_mac in self.mac_table else 'broadcast'}")

        else:
            # Broadcast if unknown destination
            for iface in self.interfaces:
                if iface != recv_iface:
                    sock = self.interface_sockets[iface]
                    dest_ip = self.interfaces[iface][1]
                    sock.sendto(data, (dest_ip, 0))

    def process_frames(self):
            while True:
                for iface, sock in self.interface_sockets.items():
                    try:
                        # print(f"[Switch] Listening on {iface}")  # Optional: comment out if too verbose
                        data, _ = sock.recvfrom(1024)

                        src_mac = data[12:16]
                        dst_mac = data[16:20]

                        print(f"[Switch] Frame received on {iface} from src_mac={src_mac.hex()} to dst_mac={dst_mac.hex()}")

                        if src_mac not in self.mac_table:
                            print(f"[Switch] Learning: {src_mac.hex()} → {iface}")
                        self.learn_source(src_mac, iface)

                        if dst_mac in self.mac_table:
                            out_iface = self.mac_table[dst_mac][0]
                            if out_iface != iface:
                                print(f"[Switch] Forwarding frame to {out_iface} for dst_mac={dst_mac.hex()}")
                            self.forward_frame(data, dst_mac, iface)
                        else:
                            print(f"[Switch] Unknown destination {dst_mac.hex()}, flooding all other ports")
                            self.forward_frame(data, dst_mac, iface)

                    except OSError as e:
                        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                            print(f"[Switch] Unexpected OS error on {iface}: {e}")
                        # else: suppress expected EAGAIN errors silently
                    except Exception as e:
                        print(f"[Switch] Unexpected non-OS error on {iface}: {e}")
                time.sleep(0.01)