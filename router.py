import time
import socket
import logging
from pdu import IPHeader, LSADatagram, HTTPDatagram
from graph import Graph
from collections import defaultdict

class Router:
    def __init__(self, router_id: str, router_interfaces: dict, direct_connections: dict):
        """
        Initializes a Router object.

        Args:
            router_id (str): Unique identifier for the router.
            router_interfaces (dict): A dictionary of router interfaces in the form {interface_name: (ip_saddr, ip_daddr)}.
            direct_connections (dict): A dictionary of directly connected networks in the form {network: (cost, interface)}.

        Raises:
            Exception: If a socket fails to initialize.
        """
        self.router_id = router_id  
        self.router_interfaces = router_interfaces
        self.direct_connections = direct_connections
        self.lsa_seq_num = 0
        self.interface_sockets = {}
        
        # Initialize sockets for each interface
        for interface, (source, _) in self.router_interfaces.items():
            try:
                int_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                int_socket.bind((source, 0))
                int_socket.setblocking(False)
                self.interface_sockets[interface] = int_socket
            except Exception as e:
                logging.error(f'Error creating socket for {interface}: {e}')

        # Create a socket for receiving datagrams
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        receive_socket.bind(('0.0.0.0', 0))
        receive_socket.setblocking(False)
        self.interface_sockets['rec'] = receive_socket

        # Initialize LSA database, timers, and forwarding table
        self.router_lsa_num = {} #check if value is greater 
        self.lsdb = {}
        self.lsa_timer = time.time()
        self.forwarding_table = {}

        # Configure logging
        logging.basicConfig(level=logging.INFO,
                            format='%(levelname)s - %(message)s',
                            handlers=[logging.FileHandler('network_app_router.log', mode='w')]
                            )



        self.initialize_lsdb()

    def initialize_lsdb(self): #correct
        """
        Initializes the Link-State Database (LSDB) with the router's direct connections.
        """
        self.lsdb[self.router_id] = []  # Initialize LSDB for this router
        for network, (cost, interface) in self.direct_connections.items():
            # Add entry for directly connected networks
            self.lsdb[self.router_id].append((network, cost, interface))


        #self.lsdb[self.router_id] = [(dst, cost, iface) for dst, (cost, iface) in self.direct_connections.items()] #this is correct


    def update_lsdb(self, adv_rtr: str, lsa: str): #correct

        lsa = [tuple(line.split(',')) for line in lsa.split('\r\n')]
        self.lsdb[adv_rtr] = [(neighbor.strip(), int(cost.strip()), interface.strip()) for neighbor, cost, interface in lsa]




    def send_initial_lsa(self): #correct

        for interface, (source, dest) in self.router_interfaces.items():
            int_socket = self.interface_sockets[interface]
            formatted_lsa_data = [f'{neighbor}, {cost}, {interface}' for neighbor, cost, interface in self.lsdb[self.router_id]]
            new_datagram = LSADatagram(ip_saddr=source, ip_daddr='224.0.0.5', adv_rtr=self.router_id, lsa_seq_num=self.lsa_seq_num, lsa_data='\r\n'.join(formatted_lsa_data))
            int_socket.sendto(new_datagram.to_bytes(), (dest, 0))
        logging.info(f'{self.router_id} has sent the initial LSA.')

    def forward_lsa(self, lsa_datagram: LSADatagram, lsa_int: str): #correct
        """
        Forwards a received LSA to all interfaces except the one on which it was received.

        Args:
            lsa_datagram (LSADatagram): The received LSA datagram to be forwarded.
            lsa_int (str): The interface on which the LSA was received.

        Returns:
            None

        Logs:
            Logs the forwarding of the LSA to each destination.
        
        Exceptions:
            Logs any exceptions that occur during forwarding.
        """
        time.sleep(0.5) # Make sure all initial LSAs are sent before forwarding an LSA
        for interface in self.router_interfaces:
            if interface != lsa_int and lsa_datagram.adv_rtr != self.router_id:
                source, dest = self.router_interfaces[interface]
                int_socket = self.interface_sockets[interface]
                new_datagram = LSADatagram(ip_saddr=source, ip_daddr='224.0.0.5', adv_rtr=lsa_datagram.adv_rtr, lsa_seq_num=lsa_datagram.lsa_seq_num, lsa_data=lsa_datagram.lsa_data)
                try:
                    int_socket.sendto(new_datagram.to_bytes(), (dest, 0))
                    logging.info(f'{self.router_id}: LSA forwarded to {dest}.')
                except Exception as e:
                    logging.error(f'Error forwarding LSA: {e}')



    def process_link_state_advertisement(self, lsa: bytes, interface: str): 
        """
        Processes a received Link-State Advertisement (LSA) and updates the LSDB. If the LSA contains new information, 
        the router broadcasts the LSA to its other interfaces.

        Args:
            lsa (bytes): The received LSA in byte form.
            interface (str): The interface on which the LSA was received.

        Returns:
            None

        Raises:
            None
        """
        # Convert the LSA packet from bytes to an LSADatagram object
        lsa_datagram = LSADatagram.from_bytes(lsa)

        # Check if the LSA is from a different router and has a newer sequence number
        if (lsa_datagram.adv_rtr != self.router_id) and (lsa_datagram.adv_rtr not in self.router_lsa_num.keys() or self.router_lsa_num[lsa_datagram.adv_rtr] < lsa_datagram.lsa_seq_num):


            # If this is a new LSA (higher sequence number), update LSDB and forward
                # Reset the LSA timer to mark reception of a new LSA
            self.lsa_timer = time.time()

                # Update the sequence number for the advertising router
            self.router_lsa_num[lsa_datagram.adv_rtr] = lsa_datagram.lsa_seq_num

                # Update the LSDB with the new LSA data
            self.update_lsdb(lsa_datagram.adv_rtr, lsa_datagram.lsa_data)

                # Forward the LSA to all other interfaces except the one it was received on
            self.forward_lsa(lsa_datagram, interface)



    def forward_datagram(self, dgram: bytes):
        """
        Forwards an HTTP datagram to the appropriate next hop based on the forwarding table.

        Args:
            dgram (bytes): The datagram received as raw bytes.

        Returns:
            None

        Logs:
            Logs the process of forwarding the datagram to the appropriate next hop.

        Raises:
            Exception: Logs any errors during the forwarding process.
        """
        try:
            # Convert the datagram bytes to an HTTPDatagram object
            http_datagram = HTTPDatagram.from_bytes(dgram)

            if http_datagram.next_hop in [connection[0] for connection in self.router_interfaces.values()]:

                ip_daddr_bin = ''.join(f'{int(octet):08b}' for octet in http_datagram.ip_daddr.split('.'))

                # Initialize variables to keep track of the longest match
                longest_prefix = None
                max_length = 0

                for network in self.forwarding_table.keys():
                    if '/' in network:
                        network_add, prefix_length = network.split('/')
                        prefix_length = int(prefix_length)
                        network_add_bin = ''.join(f'{int(octet):08b}' for octet in network_add.split('.'))

                        # Determine how many bits match between destination IP and network address
                        matching_bits = 0
                        for i in range(prefix_length):
                            if ip_daddr_bin[i] != network_add_bin[i]:
                                break
                            matching_bits += 1

                        if matching_bits > max_length:
                            max_length = matching_bits
                            longest_prefix = network

                if longest_prefix is None:
                    raise Exception("No matching prefix found for destination IP.")

                # Look up the next hop from the forwarding table
                fwd_int = self.forwarding_table[longest_prefix][0]
                fwd_socket = self.interface_sockets[fwd_int]  # Correct the socket attribute

                fwd_dgram = HTTPDatagram(
                    ip_saddr=http_datagram.ip_saddr, 
                    ip_daddr=http_datagram.ip_daddr, 
                    source_port=http_datagram.source_port, 
                    dest_port=http_datagram.dest_port, 
                    seq_num=http_datagram.seq_num, 
                    ack_num=http_datagram.ack_num, 
                    flags=http_datagram.flags, 
                    window_size=http_datagram.window_size, 
                    next_hop=self.router_interfaces[fwd_int][1], 
                    data=http_datagram.data
                )

                # Convert the datagram to bytes and forward it to the next hop
                fwd_dgram_bytes = fwd_dgram.to_bytes()
                fwd_socket.sendto(fwd_dgram_bytes, (self.router_interfaces[fwd_int][1], 0))
                logging.info(f'{self.router_id}: Forwarding packet to {fwd_dgram.next_hop} on interface {fwd_int}')
        except Exception as e:
                # Log the exception
            print(f"Error forwarding datagram: {e}")
    
    def run_route_alg(self):
        """
        Runs Dijkstra's shortest path algorithm to calculate the shortest paths to all nodes
        in the network and updates the forwarding table based on the LSDB.

        Returns:
            None
        """
        # Step 1: Create the graph

        
        graph = Graph()

        
        for router, neighbors in self.lsdb.items():
            for neighbor, cost, interface in neighbors:
                graph.add_edge(router, neighbor, cost, interface)
        
        # Step 2: Initialize Dijkstra's algorithm
        start_node = self.router_id
        # Create a set of visited nodes that has the start node only (initially)
        visited = set()  # Set of processed nodes
        visited.add(start_node)
        distances = defaultdict(lambda: float('inf'))
        paths = {node: [] for node in graph.nodes}  # Tracks the path to each node

        distances[start_node] = 0  # Distance to start node is 0
        for neighbor, cost, interface in self.lsdb.get(start_node, []):
            distances[neighbor] = cost
            paths[neighbor] = [(start_node, interface), (neighbor, interface)]

        # Step 3: Dijkstra's algorithm
        while len(visited) < len(graph.nodes):
            # Find the node 'w' with the smallest distance not yet processed
            w = min((node for node in distances if node not in visited), key=lambda node: distances[node], default=None)
            if w is None:
                break  # No remaining nodes to process

            # Mark 'w' as visited
            visited.add(w)

            # Process all unvisited neighbors of 'w'
            for neighbor, cost, interface in graph.nodes.get(w, []):
                if neighbor in visited:
                    continue  # Skip already processed neighbors

                new_distance = distances[w] + cost
                if new_distance < distances[neighbor]:
                    # Update shortest known distance and previous node/interface for the path to 'neighbor'
                    distances[neighbor] = new_distance
                    paths[neighbor] = paths[w] + [(neighbor, interface)]

        # Step 4: Construct the forwarding table based on the shortest paths
        self.forwarding_table = {}
        for node in graph.nodes:
            if node == start_node:
                self.forwarding_table[node] = (None, 0)

            if paths[node]:
                first_hop_interface = paths[node][1][1]  # First hop interface on the path to the destination node
                distance = distances[node]
                self.forwarding_table[node] = (first_hop_interface, distance)
        
        #prints the forwarding table 
        print(f"[Router {self.router_id}] Forwarding Table Updated:")
        for dest, (iface, cost) in self.forwarding_table.items():
            print(f"  → {dest} | via {iface} | cost {cost}")


    def process_datagrams(self):
        """
        Receives, processes, and forwards incoming datagrams or LSAs. It updates the LSDB and forwarding table as needed,
        and then forwards datagrams to their correct next hop.

        Returns:
            None

        Logs:
            Logs the content of the LSDB and forwarding table.
        """
        while time.time() - self.lsa_timer < 5:
            for interface in self.interface_sockets.keys():
                try:
                    new_datagram_bytes, address = self.interface_sockets[interface].recvfrom(1024)
                    new_datagram = IPHeader.from_bytes(new_datagram_bytes)
                    if new_datagram.ip_daddr == '224.0.0.5' and address[0] in [connection[1] for connection in self.router_interfaces.values()]:
                        self.process_link_state_advertisement(new_datagram_bytes, interface)
                except Exception:
                    continue

        self.run_route_alg()
        time.sleep(0.5)
        start_time = time.time()
        while time.time() - start_time < 10:
            for interface in self.interface_sockets.keys():
                try:
                    new_datagram_bytes, _ = self.interface_sockets[interface].recvfrom(1024)
                    self.forward_datagram(new_datagram_bytes)
                except Exception:
                    continue

        logging.info(f'{self.router_id} LSDB: {self.lsdb}')
        logging.info(f'{self.router_id} Forwarding Table: {self.forwarding_table}')
        self.shutdown()

    def shutdown(self):
        """
        Shuts down the router by closing all open sockets.

        Returns:
            None

        Logs:
            Logs the shutdown process of the router.
        """
        # Close all interface sockets
        for interface in self.interface_sockets.keys():
            try:
                self.interface_sockets[interface].close()
            except Exception as e:
                logging.error(f'Error closing socket for {interface}: {e}')

# Example usage
if __name__ == "__main__":
    r1_interfaces = {
        'Gi0/1': ('127.0.0.254', '127.0.0.1'), 
        'Gi0/2': ('127.248.0.1', '127.248.0.2'),
        'Gi0/3': ('127.248.4.1', '127.248.4.2')
    }
    
    r1_direct_connections = {
        '127.0.0.0/24': (0, 'Gi0/1'),
        '2.2.2.2': (3, 'Gi0/2'), 
        '3.3.3.3': (9, 'Gi0/3')
    }
    
    R1 = Router('1.1.1.1', r1_interfaces, r1_direct_connections)
    R1.shutdown()