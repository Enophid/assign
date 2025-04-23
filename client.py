import socket
import sys
import json
import os
import time
import getpass
import threading
import signal
import atexit
import hashlib
import uuid  # Add this for generating unique request IDs

class ForumClient:
    def __init__(self, server_address):
        # Parse server address - could be a hostname:port or IP:port format
        if ':' in server_address:
            self.server_host, port_str = server_address.split(':', 1)
            self.server_port = int(port_str)
        else:
            # Assume it's just a port number
            self.server_host = 'localhost'
            self.server_port = int(server_address)
            
        self.username = None
        self.commands = {
            'CRT': self.create_thread,
            'LST': self.list_threads,
            'RDT': self.read_thread,
            'RMV': self.delete_thread,
            'MSG': self.post_message,
            'EDT': self.edit_message,
            'DLT': self.delete_message,
            'UPD': self.upload_file,
            'DWN': self.download_file,
            'XIT': self.exit
        }
        
        # Create a local directory to store downloaded files
        if not os.path.exists("downloads"):
            os.makedirs("downloads")
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Register an exit handler
        atexit.register(self.clean_exit)
        
        print(f"Connecting to server at {self.server_host}:{self.server_port}")
    
    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        print("\nReceived termination signal. Cleaning up...")
        self.clean_exit()
        sys.exit(0)
    
    def clean_exit(self):
        """Ensure clean exit with logout"""
        if self.username:
            print("Logging out due to client shutdown...")
            try:
                self.logout(silent=True)
            except:
                pass
    
    def show_commands(self):
        """Display available commands"""
        return input("Enter one of the following commands: CRT, MSG, DLT, EDT, LST, RDT, UPD, DWN, RMV, XIT: ").strip()
    
    def start(self):
        """Start the client interface"""
        print("Welcome to the forum")
        
        # Start with authentication
        self.authenticate()
        
        # Main command loop
        while True:
            if not self.username:
                # If not logged in, try to authenticate
                self.authenticate()
                if not self.username:
                    # Exit if authentication failed
                    break
            
            # Show available commands and get user input
            command = self.show_commands()
            
            if command == 'XIT':
                self.exit()
                break
            
            # Split command and arguments
            parts = command.split()
            cmd = parts[0] if parts else ''
            
            if cmd in self.commands:
                try:
                    if len(parts) > 1:
                        self.commands[cmd](*parts[1:])
                    else:
                        self.commands[cmd]()
                except Exception as e:
                    print(f"Error executing command: {e}")
            else:
                print("Invalid command")
    
    def authenticate(self):
        """Handle the authentication process"""
        while True:
            username = input("Enter username: ").strip()
            if not username:
                print("Username cannot be empty.")
                continue
                
            # First check if username exists
            max_attempts = 3  # Maximum attempts to try the command if there's a timeout
            attempt = 0
            
            while attempt < max_attempts:
                response = self.check_username(username)
                
                # Handle connection errors more gracefully
                if response['status'] == 'error' and 'timed out' in response.get('message', '').lower():
                    attempt += 1
                    if attempt < max_attempts:
                        print(f"Connection failed. Retrying ({attempt}/{max_attempts})...")
                        time.sleep(1)  # Wait before retrying
                        continue
                    else:
                        print("Couldn't connect to server. Please check if the server is running and try again later.")
                        return
                
                # Process the response
                if response['status'] == 'error':
                    # Check if the user is already logged in
                    if "already logged in" in response.get('message', ''):
                        print(f"{username} has already logged in")
                        break  # Exit the retry loop but continue the main auth loop
                    # Handle other errors
                    else:
                        print(f"Error: {response['message']}")
                        break  # Exit the retry loop but continue the main auth loop
                
                if response['status'] == 'exists':
                    # Username exists, try to login with password
                    password = getpass.getpass("Enter password: ")
                    if not password:
                        print("Password cannot be empty.")
                        break  # Exit the retry loop but continue the main auth loop
                    
                    # Retry login if there's a timeout
                    login_attempt = 0
                    while login_attempt < max_attempts:
                        login_response = self.login(username, password)
                        
                        # Handle connection errors
                        if login_response['status'] == 'error' and 'timed out' in login_response.get('message', '').lower():
                            login_attempt += 1
                            if login_attempt < max_attempts:
                                print(f"Connection failed. Retrying login ({login_attempt}/{max_attempts})...")
                                time.sleep(1)
                                continue
                            else:
                                print("Couldn't connect to server. Please check if the server is running and try again later.")
                                return
                        
                        if login_response['status'] == 'success':
                            self.username = username
                            print("Welcome to the forum")
                            return
                        else:
                            # Check if the user is already logged in
                            if "already logged in" in login_response.get('message', ''):
                                print(f"{username} has already logged in")
                                break
                            else:
                                print("Invalid password")
                                break
                    
                    break  # Exit the retry loop but continue the main auth loop
                    
                elif response['status'] == 'new':
                    password = getpass.getpass("New user, enter password: ")
                    if not password:
                        print("Password cannot be empty.")
                        break
                    
                    # Retry registration if there's a timeout
                    register_attempt = 0
                    while register_attempt < max_attempts:
                        register_response = self.register(username, password)
                        
                        # Handle connection errors
                        if register_response['status'] == 'error' and 'timed out' in register_response.get('message', '').lower():
                            register_attempt += 1
                            if register_attempt < max_attempts:
                                print(f"Connection failed. Retrying registration ({register_attempt}/{max_attempts})...")
                                time.sleep(1)
                                continue
                            else:
                                print("Couldn't connect to server. Please check if the server is running and try again later.")
                                return
                        
                        if register_response['status'] == 'success':
                            self.username = username
                            print("Welcome to the forum")
                            return
                        else:
                            print(f"Registration failed: {register_response['message']}")
                            break
                    
                    break  # Exit the retry loop but continue the main auth loop
                else:
                    # Handle unexpected status
                    print(f"Unexpected response from server: {response.get('status')}")
                    break  # Exit the retry loop but continue the main auth loop
                
                # If we get here, we need to exit the retry loop
                break
    
    def send_udp_request(self, request_data):
        """Send a request to the server via UDP and get the response"""
        # Maximum number of retries
        max_retries = 3
        # Initial timeout in seconds - increase for better reliability
        timeout = 5.0
        
        # Add a unique request ID to the request data
        request_id = str(uuid.uuid4())
        request_data['request_id'] = request_id
        
        for attempt in range(max_retries):
            # Create a new socket for each request to avoid connection issues
            request_socket = None
            try:
                # Create and configure socket
                request_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                request_socket.settimeout(timeout)
                
                # Convert request to JSON and send
                request_json = json.dumps(request_data).encode('utf-8')
                server_address = (self.server_host, self.server_port)
                
                # Print connection info on first attempt only
                if attempt == 0:
                    print(f"Connecting to server at {self.server_host}:{self.server_port}...")
                
                request_socket.sendto(request_json, server_address)
                
                # Wait for response
                response_data, server = request_socket.recvfrom(4096)
                
                # Parse response
                response = json.loads(response_data.decode('utf-8'))
                
                # Check if response is for the current request
                if response.get('request_id') != request_id:
                    print("Received response for different request, ignoring")
                    if attempt < max_retries - 1:
                        continue
                    else:
                        return {'status': 'error', 'message': 'Received mismatched response ID'}
                
                # Return response
                return response
                
            except socket.timeout:
                # Exponential backoff - increase timeout for next attempt
                timeout *= 1.5
                if attempt < max_retries - 1:
                    print(f"Request timed out. Retrying ({attempt+1}/{max_retries})...")
                    time.sleep(0.5)  # Add a small delay between retries
                else:
                    print("Request timed out. Server may be unavailable.")
                    # Try to ping the server to check connectivity
                    try:
                        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        test_socket.settimeout(1.0)
                        test_message = json.dumps({"test": "ping"}).encode('utf-8')
                        print(f"Testing connectivity to {self.server_host}:{self.server_port}...")
                        test_socket.sendto(test_message, (self.server_host, self.server_port))
                        test_socket.close()
                    except Exception as e:
                        print(f"Connection test failed: {e}")
                    
                    return {'status': 'error', 'message': 'Request timed out'}
            except ConnectionResetError as e:
                print(f"Connection reset by server. Retrying ({attempt+1}/{max_retries})...")
                if attempt < max_retries - 1:
                    time.sleep(1)  # Longer delay for connection reset errors
                else:
                    return {'status': 'error', 'message': str(e)}
            except Exception as e:
                print(f"Error communicating with server: {e}")
                if attempt < max_retries - 1:
                    print(f"Retrying ({attempt+1}/{max_retries})...")
                    time.sleep(1)
                else:
                    return {'status': 'error', 'message': str(e)}
            finally:
                # Always close the socket
                if request_socket:
                    try:
                        request_socket.close()
                    except:
                        pass
    
    # Authentication Commands
    def check_username(self, username):
        """Check if username exists"""
        request = {
            'command': 'check_username',
            'username': username
        }
        
        return self.send_udp_request(request)
    
    def login(self, username, password):
        """Login with existing account"""
        request = {
            'command': 'login',
            'username': username,
            'password': password
        }
        
        return self.send_udp_request(request)
    
    def logout(self, silent=False):
        """Logout from the server"""
        if not self.username:
            if not silent:
                print("You are not logged in")
            return
        
        request = {
            'command': 'logout',
            'username': self.username
        }
        
        try:
            response = self.send_udp_request(request)
            
            if response['status'] == 'success':
                if not silent:
                    print(response['message'])
                self.username = None
            else:
                if not silent:
                    print(f"Logout failed: {response['message']}")
        except Exception as e:
            if not silent:
                print(f"Error during logout: {e}")
            self.username = None  # Still clear the username locally
    
    def register(self, username, password):
        """Register a new account"""
        request = {
            'command': 'register',
            'username': username,
            'password': password
        }
        
        return self.send_udp_request(request)
    
    # Thread Commands
    def create_thread(self, *args):
        """Create a new discussion thread (CRT)"""
        if not args or len(args) != 1:
            print("Usage: CRT thread_title")
            return
        
        title = args[0]
        
        request = {
            'command': 'create_thread',
            'username': self.username,
            'title': title
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            print(f"Thread {title} created")
        else:
            print(f"Thread {title} exists")
    
    def list_threads(self):
        """List all available threads (LST)"""
        request = {
            'command': 'list_threads',
            'username': self.username
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            threads = response.get('threads', [])
            
            if not threads:
                print("No threads to list")
                return
            
            print("The list of active threads:")
            # Print just the thread titles/IDs in a simple list format
            for thread in threads:
                thread_id = thread.get('id', 'Unknown')
                print(thread_id)
        else:
            print(f"Failed to list threads: {response.get('message', 'Unknown error')}")
    
    def read_thread(self, *args):
        """Read a thread's messages (RDT)"""
        if not args or len(args) != 1:
            print("Incorrect syntax for RDT")
            return
        
        thread_id = args[0]
        
        request = {
            'command': 'get_thread',
            'username': self.username,
            'thread_id': thread_id
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            thread = response['thread']
            
            if not thread['messages'] and not thread['files']:
                print(f"Thread {thread_id} is empty")
                return
            
            # Print messages
            for i, msg in enumerate(thread['messages'], 1):
                if not msg.get('deleted', False):
                    print(f"{i} {msg['author']}: {msg['content']}")
            
            # Print files
            for file in thread['files']:
                print(f"{file['uploader']} uploaded {file['original_name']}")
        else:
            print(f"Thread {thread_id} does not exist")
    
    def delete_thread(self, *args):
        """Remove a thread (RMV)"""
        if not args or len(args) != 1:
            print("Usage: RMV thread_id")
            return
        
        thread_id = args[0]
        
        request = {
            'command': 'delete_thread',
            'username': self.username,
            'thread_id': thread_id
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            print("Thread removed")
        else:
            print("Thread cannot be removed")
    
    # Message Commands
    def post_message(self, *args):
        """Post a message to a thread (MSG)"""
        if not args or len(args) < 2:
            print("Usage: MSG thread_id message")
            return
        
        thread_id = args[0]
        content = ' '.join(args[1:])
        
        request = {
            'command': 'post_message',
            'username': self.username,
            'thread_id': thread_id,
            'content': content
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            print(f"Message posted to {thread_id} thread")
        else:
            print(f"Failed to post to {thread_id} thread")
    
    def edit_message(self, *args):
        """Edit a message (EDT)"""
        if not args or len(args) < 3:
            print("Usage: EDT thread_id message_id new_message")
            return
        
        thread_id = args[0]
        message_id = args[1]
        content = ' '.join(args[2:])
        
        request = {
            'command': 'edit_message',
            'username': self.username,
            'thread_id': thread_id,
            'message_id': message_id,
            'content': content
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            print("The message has been edited")
        else:
            print("The message belongs to another user and cannot be edited")
    
    def delete_message(self, *args):
        """Delete a message (DLT)"""
        if not args or len(args) != 2:
            print("Usage: DLT thread_id message_id")
            return
        
        thread_id, message_id = args
        
        request = {
            'command': 'delete_message',
            'username': self.username,
            'thread_id': thread_id,
            'message_id': message_id
        }
        
        response = self.send_udp_request(request)
        
        if response['status'] == 'success':
            print("The message has been deleted")
        else:
            print("The message belongs to another user and cannot be deleted")
    
    # File Commands (using TCP)
    def upload_file(self, *args):
        """Upload a file to a thread (UPD)"""
        if not args or len(args) != 2:
            print("Usage: UPD thread_id file_name")
            return
        
        thread_id, filepath = args
        
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return
        
        # Get file information
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        
        # Calculate file checksum
        file_checksum = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                file_checksum.update(chunk)
        checksum_hex = file_checksum.hexdigest()
        
        # Create a TCP socket for file transfer
        try:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (self.server_host, self.server_port)
            tcp_socket.connect(server_address)
            
            # Send file information header
            header = {
                'operation': 'upload',
                'username': self.username,
                'thread_id': thread_id,
                'filename': filename,
                'file_size': file_size,
                'checksum': checksum_hex
            }
            
            tcp_socket.send(json.dumps(header).encode('utf-8'))
            
            # Wait for server acknowledgment
            response_data = tcp_socket.recv(1024)
            response = json.loads(response_data.decode('utf-8'))
            
            if response['status'] != 'ready':
                print(f"Upload failed: {response.get('message', 'Server not ready')}")
                tcp_socket.close()
                return
            
            # Send file data
            with open(filepath, 'rb') as f:
                bytes_sent = 0
                
                while bytes_sent < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    tcp_socket.send(chunk)
                    bytes_sent += len(chunk)
            
            # Get final confirmation
            response_data = tcp_socket.recv(1024)
            response = json.loads(response_data.decode('utf-8'))
            
            if response['status'] == 'success':
                server_checksum = response.get('checksum')
                if server_checksum and server_checksum == checksum_hex:
                    print(f"{filename} uploaded to {thread_id} thread")
            else:
                print(f"Upload failed: {response.get('message', 'Unknown error')}")
            
        except Exception as e:
            print(f"Error uploading file: {e}")
        finally:
            tcp_socket.close()
    
    def download_file(self, *args):
        """Download a file from a thread (DWN)"""
        if not args or len(args) != 2:
            print("Usage: DWN thread_id file_name")
            return
        
        thread_id, filename = args
        
        # Create a TCP socket for file transfer
        try:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (self.server_host, self.server_port)
            tcp_socket.connect(server_address)
            
            # Send file information header
            header = {
                'operation': 'download',
                'username': self.username,
                'thread_id': thread_id,
                'filename': filename
            }
            
            tcp_socket.send(json.dumps(header).encode('utf-8'))
            
            # Wait for server response with file information
            response_data = tcp_socket.recv(1024)
            response = json.loads(response_data.decode('utf-8'))
            
            if response['status'] != 'ready':
                print(f"File does not exist in Thread {thread_id}")
                tcp_socket.close()
                return
            
            file_size = response.get('file_size', 0)
            original_name = response.get('original_name', filename)
            expected_checksum = response.get('checksum')
            
            # Send acknowledgment to start transfer
            ack = {'status': 'ready'}
            tcp_socket.send(json.dumps(ack).encode('utf-8'))
            
            # Prepare to receive file - save to current working directory as specified
            save_path = original_name
            
            # Calculate checksum while receiving file
            file_checksum = hashlib.md5()
            
            with open(save_path, 'wb') as f:
                bytes_received = 0
                
                while bytes_received < file_size:
                    chunk = tcp_socket.recv(min(4096, file_size - bytes_received))
                    if not chunk:
                        break
                    file_checksum.update(chunk)
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            # Verify checksum
            calculated_checksum = file_checksum.hexdigest()
            if expected_checksum and calculated_checksum == expected_checksum:
                print(f"{filename} successfully downloaded and verified")
            elif expected_checksum:
                print("Warning: Checksum verification failed. File may be corrupted.")
                print(f"Expected: {expected_checksum}")
                print(f"Received: {calculated_checksum}")
            else:
                print(f"{filename} successfully downloaded")
            
        except Exception as e:
            print(f"Error downloading file: {e}")
        finally:
            tcp_socket.close()
    
    def exit(self):
        """Exit the application (XIT)"""
        if self.username:
            # Logout before exiting
            self.logout()
        
        print("Goodbye")

if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python client.py <server_address>")
        print("  server_address can be 'hostname:port' or just 'port' (default host: localhost)")
        sys.exit(1)
    
    try:
        server_address = sys.argv[1]
        
        client = ForumClient(server_address)
        client.start()
    except ValueError:
        print("Invalid server address format")
        print("Usage: python client.py <server_address>")
        print("  server_address can be 'hostname:port' or just 'port' (default host: localhost)")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting client: {e}")
        sys.exit(1) 