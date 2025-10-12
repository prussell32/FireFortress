import socket

HOST = '127.0.0.1'    # The server's hostname or IP address
PORT = 65432   # The port used by the server    
TIMEOUT = 15    # Timeout duration in seconds

def server_start():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(15)  # Set a timeout for socket operations
            
            s.bind((HOST, int(PORT)))    # Bind the socket to the address and port
            s.listen()              # Listen for incoming connections
            print(f"server listening on {HOST}:{PORT} with {TIMEOUT}s timeout...")
            
            try:
                conn, addr = s.accept()    # Accept a connection from client
            except socket.timeout:
                print("Socket timed out waiting for a connection.")
                return
              
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)    # Receive data from the client
                    if not data:
                        print("Client disconnected.")
                        break
                    print("Received data:", data.decode())
                    conn.sendall(data)    # Echo the received data back to the client
                    
                conn.close()   # Close the connection
                print("Connection closed.")
                
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    server_start()