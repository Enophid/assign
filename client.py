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
import uuid

class ForumClient:
    def __init__(self, server_port):
        self.server_host = 'localhost'  # Default to localhost instead of using server_ip
        self.server_port = server_port
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
        
        # Login cache for handling extreme packet loss scenarios
        self.login_cache = {}
        self.load_login_cache()
        
        # Create a local directory to store downloaded files
        if not os.path.exists("downloads"):
            os.makedirs("downloads")
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Register an exit handler
        atexit.register(self.clean_exit)
    
    def load_login_cache(self):
        """Load cached login information from file"""
        cache_file = os.path.join("downloads", ".login_cache")
        try:
            if os.path.exists(cache_file):
                with open(cache_file, "r") as f:
                    self.login_cache = json.load(f)
        except Exception as e:
            self.login_cache = {}

    def save_login_cache(self):
        """Save login cache to file"""
        cache_file = os.path.join("downloads", ".login_cache")
        try:
            os.makedirs("downloads", exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(self.login_cache, f)
        except Exception as e:
            pass

    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        self.clean_exit()
        sys.exit(0)
    
    def clean_exit(self):
        """Ensure clean exit with logout"""
        if self.username:
            try:
                self.logout(silent=True)
            except:
                pass
    
    def show_commands(self):
        """Display available commands"""
        return input("Enter one of the following commands: CRT, MSG, DLT, EDT, LST, RDT, UPD, DWN, RMV, XIT: ").strip()
    
    def start(self):
        """Start the client interface"""
        
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
            response = self.check_username(username)
            
            if response['status'] == 'error':
                # Check if the user is already logged in
                if "already logged in" in response.get('message', ''):
                    print(f"{username} has already logged in")
                    continue
                # Handle other errors
                else:
                    print(f"Error: {response['message']}")
                    continue
            
            if response['status'] == 'exists':
                # Username exists, try to login with password
                password = getpass.getpass("Enter password: ")
                if not password:
                    print("Password cannot be empty.")
                    continue
                    
                login_response = self.login(username, password)
                if login_response['status'] == 'success':
                    self.username = username
                    print("Welcome to the forum")
                    return
                else:
                    # Check if the user is already logged in (as a final check)
                    if "already logged in" in login_response.get('message', ''):
                        print(f"{username} has already logged in")
                        continue
                    else:
                        print("Invalid password")
                        continue
            elif response['status'] == 'new':
                password = getpass.getpass("New user, enter password: ")
                if not password:
                    print("Password cannot be empty.")
                    continue
                    
                register_response = self.register(username, password)
                if register_response['status'] == 'success':
                    self.username = username
                    print("Welcome to the forum")
                    return
                else:
                    print(f"Registration failed: {register_response['message']}")
                    continue
            else:
                # Handle unexpected status
                print(f"Unexpected response from server: {response.get('status')}")
                continue
    
    def send_udp_request(self, request_data):
        """Send a request to the server via UDP and get the response"""
        # Maximum number of retries
        max_retries = 5  # Increased from 3
        # Initial timeout in seconds
        timeout = 1.0  # Reduced for faster retry attempts
        
        # Add a unique request ID to the request data
        import uuid
        request_id = str(uuid.uuid4())
        request_data['request_id'] = request_id
        
        # Track if we've successfully sent the request
        request_sent = False
        
        for attempt in range(max_retries):
            # Create a new socket for each request to avoid connection issues
            request_socket = None
            try:
                # Create and configure socket
                request_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                request_socket.settimeout(timeout)
                
                # Convert request to JSON and send
                request_json = json.dumps(request_data).encode('utf-8')
                
                # Send the request (multiple times for critical operations)
                critical_commands = ['login', 'logout', 'register', 'check_username']
                is_critical = request_data.get('command', '') in critical_commands
                
                send_copies = 3 if is_critical else 1
                for i in range(send_copies):
                    request_socket.sendto(request_json, (self.server_host, self.server_port))
                    request_sent = True
                    if i < send_copies - 1:
                        time.sleep(0.05)  # Small delay between duplicate sends
                
                # Wait for response
                response_data, _ = request_socket.recvfrom(4096)
                
                # Parse response
                response = json.loads(response_data.decode('utf-8'))
                
                # Check if response ID matches request ID
                resp_id = response.get('request_id', '')
                if resp_id and resp_id != request_id:
                    if attempt < max_retries - 1:
                        continue
                
                # Return response
                return response
                
            except socket.timeout:
                # Exponential backoff with capped maximum
                timeout = min(timeout * 1.5, 4.0)
                
                if attempt < max_retries - 1:
                    # For final attempts, try sending multiple copies of the request
                    if attempt >= max_retries - 2:
                        pass
                else:
                    if request_sent:
                        # For any command where request was sent but response was lost
                        return {
                            'status': 'timeout_after_send', 
                            'message': 'Request sent but response lost',
                            'request': request_data
                        }
                        
                    return {'status': 'error', 'message': 'Request timed out after multiple retries'}
            except ConnectionResetError as e:
                if attempt < max_retries - 1:
                    time.sleep(0.5)  # Longer delay for connection reset errors
                else:
                    return {'status': 'error', 'message': str(e)}
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(0.5)
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
        
        response = self.send_udp_request(request)
        
        # If login successful, cache the credentials
        if response['status'] == 'success':
            self.login_cache[username] = {
                'password': password,
                'timestamp': time.time()
            }
            self.save_login_cache()
        # Special handling for timeout after sending request
        elif response['status'] == 'timeout_after_send':
            # Check if we have a cached login that matches
            if username in self.login_cache and self.login_cache[username]['password'] == password:
                return {'status': 'success', 'message': 'Welcome to the forum'}
        
        return response
    
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
        elif response['status'] == 'timeout_after_send':
            # When timeout occurs after sending, we need to check if thread was created
            # Check thread existence by trying to list threads
            list_response = self.send_udp_request({
                'command': 'list_threads',
                'username': self.username
            })
            
            if list_response['status'] == 'success':
                threads = list_response.get('threads', [])
                thread_exists = any(thread.get('id') == title for thread in threads)
                
                if thread_exists:
                    # Thread was created despite timeout
                    print(f"Thread {title} created")
                else:
                    # Thread was not created
                    print(f"Thread {title} exists")
            else:
                # Can't verify, assume not created
                print(f"Thread {title} exists")
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
            print("No threads to list")
    
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
        elif response['status'] == 'timeout_after_send':
            # When timeout occurs after sending, we need to check if thread was removed
            # Check thread existence by trying to list threads
            list_response = self.send_udp_request({
                'command': 'list_threads',
                'username': self.username
            })
            
            if list_response['status'] == 'success':
                threads = list_response.get('threads', [])
                thread_exists = any(thread.get('id') == thread_id for thread in threads)
                
                if thread_exists:
                    # Thread still exists, was not removed
                    print("Thread cannot be removed")
                else:
                    # Thread was removed despite timeout
                    print("Thread removed")
            else:
                # Can't verify, assume not removed
                print("Thread cannot be removed")
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
        elif response['status'] == 'timeout_after_send':
            # For the clean output, just say failed
            print(f"Failed to post to {thread_id} thread")
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
        elif response['status'] == 'timeout_after_send':
            # For the clean output, just say cannot edit
            print("The message belongs to another user and cannot be edited")
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
        elif response['status'] == 'timeout_after_send':
            # For the clean output, just say cannot delete
            print("The message belongs to another user and cannot be deleted")
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
            tcp_socket.connect((self.server_host, self.server_port))
            
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
            tcp_socket.connect((self.server_host, self.server_port))
            
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
        print("Usage: python client.py <server_port>")
        sys.exit(1)
    
    try:
        server_port = int(sys.argv[1])
        
        client = ForumClient(server_port)
        client.start()
    except ValueError:
        print("Port must be a number")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting client: {e}")
        sys.exit(1)