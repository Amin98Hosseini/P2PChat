import socket
import threading
import json
import os

class TCPChatServer:
    def __init__(self):
        self.clients = {}  # client_id -> socket
        self.client_ids = {}  # socket -> client_id
        
    def handle_client(self, client_socket, client_address):
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                message_data = json.loads(data.decode('utf-8'))
                
                # Registration
                if 'register' in str(message_data).lower() or 'id' in message_data:
                    client_id = message_data.get('id', '')
                    self.clients[client_id] = client_socket
                    self.client_ids[client_socket] = client_id
                    print(f"Client {client_id} connected from {client_address}")
                    
                elif 'type' in message_data:
                    if message_data['type'] == 'text':
                        recipient = message_data.get('recipient', '')
                        content = message_data.get('content', '')
                        
                        # Forward to recipient
                        if recipient in self.clients:
                            try:
                                response = {
                                    'sender': self.client_ids[client_socket],
                                    'type': 'text',
                                    'content': content
                                }
                                self.clients[recipient].send(json.dumps(response).encode('utf-8'))
                            except Exception as e:
                                print(f"Could not send to {recipient}: {e}")
                        else:
                            print(f"Recipient {recipient} not found")
                            
                    elif message_data['type'] == 'file':
                        recipient = message_data.get('recipient', '')
                        filename = message_data.get('filename', '')
                        
                        if recipient in self.clients:
                            try:
                                response = {
                                    'sender': self.client_ids[client_socket],
                                    'type': 'file',
                                    'filename': filename,
                                    'data': message_data['data']
                                }
                                self.clients[recipient].send(json.dumps(response).encode('utf-8'))
                            except Exception as e:
                                print(f"Could not send file to {recipient}: {e}")
                        else:
                            print(f"Recipient {recipient} not found")
                            
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            # Clean up on disconnect
            if client_socket in self.client_ids:
                client_id = self.client_ids[client_socket]
                del self.clients[client_id]
                del self.client_ids[client_socket]
                print(f"Client {client_id} disconnected")
                
    def start_server(self, host='192.168.1.101', port=8888):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((host, port))
            server_socket.listen(5)
            print(f"Server listening on {host}:{port}")
            
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = TCPChatServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("Server stopped")
