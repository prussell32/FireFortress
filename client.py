import socket

HOST = '127.0.0.1'  # The server IP

PORT = 65432        # The server port

TIMEOUT = 15        # Timeout duration in seconds

def client_start():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
            c.settimeout(TIMEOUT)    #Timeout for connection

            c.connect((HOST, PORT))    # Connect to the server
            print(f"connected to server {HOST}:{PORT}")
            
            message = "Hello, Server!"    # Message to send to the server
            c.sendall(message.encode())    # Send data to the server
            print(f"Sent to server: {message}")
            
            data = c.recv(1024)   # Receive data from the server
            print(f"Received from the server: {data.decode()}")
            
    except socket.timeout:
        print("Connection timed out after 15 seconds.")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
        
if __name__ == '__main__':
    client_start()