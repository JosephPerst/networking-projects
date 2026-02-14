import threading
import time
from tcp_client import Client
from router import Router
from tcp_server import Server
from switch import Switch # this is the switch class, for testing ONLY it has no real MAC addresses

class NetworkApp:
    """
    Represents a network application that simulates a network of routers, a web server, 
    and a client interacting in a network environment. The application uses threads to 
    manage the concurrent activities of routers processing datagrams and the server-client interaction.

    Attributes:
        routers (list): A list of `Router` objects that form the network.
        web_server (Server): The web server instance that responds to client requests.
        svr_thread (threading.Thread): A thread to run the server concurrently.
        web_client (Client): The client instance that sends requests to the server.
    """

    def __init__(self, router_data):
        """
        Initializes the NetworkApp with a set of routers and a server.

        Args:
            router_data (list): A list of tuples containing interface and direct connection data for each router.
        """
        
        self.routers = []
        router_id = 1

        # Create Router instances
        for interfaces, direct_connections in router_data:
            self.routers.append(Router(f'{router_id}.{router_id}.{router_id}.{router_id}', interfaces, direct_connections))
            router_id += 1
        print('The routers have been created!')
        
        
        # using the fake switches to do this test. IP and MACs are given by chat
        switch_interfaces = {
            'sw0': ('127.0.0.10', '127.0.0.11'),
            'sw1': ('127.0.0.12', '127.0.0.13'),
            'sw2': ('127.0.0.14', '127.0.0.15'),
        }
        self.switch = Switch(switch_interfaces)
        self.sw_thread = threading.Thread(target=self.switch.process_frames)
        self.sw_thread.daemon = True
        self.sw_thread.start()
        print('The switch is running!')

        # Create and run the server in a separate thread
        self.web_server = Server(frame_size=128, gateway='127.0.0.1')
        self.svr_thread = threading.Thread(target=self.web_server.run_server)
        self.svr_thread.start()
        print('The web server is running!')


    def run_app(self):
        """
        Runs the network application, which includes starting routers, sending link-state advertisements,
        creating a client to request resources, and handling server-client interaction.
        """
        # Start routers in separate threads
        router_threads = []
        for router in self.routers:
            rtr_thread = threading.Thread(target=router.process_datagrams)
            router_threads.append(rtr_thread)
            rtr_thread.start()

        # Routers send initial link-state advertisements
        for router in self.routers:
            router.send_initial_lsa()

        time.sleep(10)  # Allow routers time to exchange LSAs and update their forwarding tables
        print('Routers are ready.')

        # Create and run the client
        self.web_client = Client()
        print('The web client is ready to send the request.')

        # Client requests a resource from the server (GET)
        # Prompt user for method and resource
        
        method = input("Enter HTTP method (GET or POST): ").strip().upper()
        resource = input("Enter the resource to request (e.g., /index.html or /post.html): ").strip()

        # If POST, also prompt for data
        data = None
        if method == "POST":
            data = input("Enter the POST data (e.g., form content): ").strip()

        # Create and run the client with input
        client = Client(frame_size=128, gateway='127.128.0.1')
        response = client.request_resource(resource, method=method, data=data)
        print(f"[Client] Response to {method}:", response)

        # Give server time to process the POST
        time.sleep(1)

        # Now create a new client for the GET request
        get_client = Client(frame_size=128, gateway='127.128.0.1')

        print('New client instance created for the GET request.')

        # Perform full GET request flow with handshake done
        response = get_client.request_resource(resource)
        print("[Client] Response to GET:", response)
                      


        print('The web client has requested and received the resource.')

        time.sleep(0.5)  # Allow routers and client to complete processing

        # Ensure all router threads finish their tasks
        for thread in router_threads:
            thread.join(2.5)

        # Shut down the server and close sockets
        self.web_server.close_server()
        print('The network application is shutdown!')


if __name__ == "__main__":
    # Define router interfaces and direct connections
    router_int_con = [
        ({'Gi0/1': ('127.0.0.254', '127.0.0.1'),
          'Gi0/2': ('127.248.0.1', '127.248.0.2'),
          'Gi0/3': ('127.248.4.1', '127.248.4.2')},
         {'127.0.0.0/24': (0, 'Gi0/1'),
          '2.2.2.2': (3, 'Gi0/2'),
          '3.3.3.3': (9, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.0.2', '127.248.0.1'),
          'Gi0/2': ('127.30.0.254', '127.30.0.1'),
          'Gi0/3': ('127.248.12.1', '127.248.12.2'),
          'Gi0/4': ('127.248.8.1', '127.248.8.2')},
         {'127.30.0.0/24': (0, 'Gi0/2'),
          '1.1.1.1': (3, 'Gi0/1'),
          '3.3.3.3': (5, 'Gi0/4'),
          '4.4.4.4': (12, 'Gi0/3')}),

          ({'Gi0/1': ('127.248.4.2', '127.248.4.1'),
          'Gi0/2': ('127.248.8.2', '127.248.8.1'),
          'Gi0/3': ('127.248.16.1', '127.248.16.2'),
          'Gi0/4': ('127.10.0.254', '127.10.0.1')},
         {'127.10.0.0/24': (0, 'Gi0/4'),
          '1.1.1.1': (9, 'Gi0/1'),
          '2.2.2.2': (5, 'Gi0/2'),
          '5.5.5.5': (10, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.12.2', '127.248.12.1'),
          'Gi0/2': ('127.40.0.254', '127.40.0.1'),
          'Gi0/3': ('127.248.24.1', '127.248.24.2'),
          'Gi0/4': ('127.248.20.1', '127.248.20.2')},
         {'127.40.0.0/24': (0, 'Gi0/2'),
          '2.2.2.2': (12, 'Gi0/1'),
          '5.5.5.5': (4, 'Gi0/4'),
          '6.6.6.6': (10, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.16.2', '127.248.16.1'),
          'Gi0/2': ('127.248.20.2', '127.248.20.1'),
          'Gi0/3': ('127.248.28.1', '127.248.28.2')},
         {'127.20.0.0/24': (0, 'Gi0/4'),
          '3.3.3.3': (10, 'Gi0/1'),
          '4.4.4.4': (4, 'Gi0/2'),
          '6.6.6.6': (5, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.24.2', '127.248.24.1'),
          'Gi0/2': ('127.248.28.2', '127.248.28.1'),
          'Gi0/3': ('127.128.0.254', '127.128.0.1')},
         {'127.128.0.0/24': (0, 'Gi0/3'),
          '4.4.4.4': (10, 'Gi0/1'),
          '5.5.5.5': (5, 'Gi0/2')})
    ]

    # Initialize and run the network application
    app = NetworkApp(router_int_con)
    app.run_app()
