import socket
import sys
import threading
import json
import os
import time
import re
import hashlib
import uuid
import random

class ForumServer:
    def __init__(self, port):
        self.port = port
        self.users = {}  # username -> password (loaded from credentials.txt)
        self.active_users = set()  # currently logged in users
        self.lock = threading.Lock()  # for thread safety in concurrent mode
        self.threads = {}  # Store thread information - key will be the thread title
        # No longer need the next_thread_id since we're using titles directly
        
        # Request cache for handling duplicated requests due to retransmissions
        self.request_cache = {}
        self.request_cache_lock = threading.Lock()
        self.request_cache_ttl = 60  # Cache TTL in seconds

        # Create data directory if it doesn't exist
        if not os.path.exists("server_data"):
            os.makedirs("server_data")
        if not os.path.exists("server_data/files"):
            os.makedirs("server_data/files")
            
        # Load existing data
        self.load_credentials()
        self.load_threads()
        
        print("Waiting for clients")
    
    def load_credentials(self):
        """Load credentials from credentials.txt file"""
        try:
            if os.path.exists("credentials.txt"):
                with open("credentials.txt", "r") as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.strip():  # Skip empty lines
                            parts = line.strip().split(" ", 1)
                            if len(parts) == 2:
                                username, password = parts
                                self.users[username] = password
        except Exception as e:
            pass
    
    def save_credentials(self, username, password):
        """Append a new username/password to credentials.txt"""
        try:
            with open("credentials.txt", "a") as f:
                f.write(f"{username} {password}\n")
            return True
        except Exception as e:
            print(f"Error saving credentials: {e}")
            return False
    
    def load_threads(self):
        """Load threads from threads.json file"""
        try:
            if os.path.exists("server_data/threads.json"):
                with open("server_data/threads.json", "r") as f:
                    old_threads_data = json.load(f)
                    
                    # Convert old format threads (numeric IDs) to new format (title as key)
                    new_threads = {}
                    for _, thread_data in old_threads_data.items():
                        title = thread_data.get('title')
                        if title:
                            # Remove the id field since we're using title as identifier
                            if 'id' in thread_data:
                                del thread_data['id']
                                
                            # Store thread with title as key
                            new_threads[title] = thread_data
                    
                    self.threads = new_threads
        except Exception as e:
            self.threads = {}
            # Create an empty threads file
            with open("server_data/threads.json", "w") as f:
                json.dump({}, f)
    
    def save_threads(self):
        """Save threads to threads.json file"""
        try:
            with open("server_data/threads.json", "w") as f:
                json.dump(self.threads, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving threads: {e}")
            return False
    
    def start(self):
        """Start the server with both UDP and TCP sockets"""
        # Start UDP server for command handling
        udp_thread = threading.Thread(target=self.run_udp_server)
        udp_thread.daemon = True
        udp_thread.start()
        
        # Start TCP server for file transfers
        tcp_thread = threading.Thread(target=self.run_tcp_server)
        tcp_thread.daemon = True
        tcp_thread.start()
        
        # Start cleanup thread for handling stale connections
        cleanup_thread = threading.Thread(target=self.run_connection_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        try:
            while True:
                time.sleep(1)  # Keep main thread alive
        except KeyboardInterrupt:
            sys.exit(0)  # Exit silently without the shutdown message
    
    def run_udp_server(self):
        """Run the UDP server for handling commands"""
        # Create UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(('0.0.0.0', self.port))
        
        while True:
            try:
                data, client_address = udp_socket.recvfrom(4096)
                
                # Handle message in a separate thread for concurrent access
                threading.Thread(
                    target=self.handle_udp_message,
                    args=(data, client_address, udp_socket)
                ).start()
                
            except Exception as e:
                print(f"Error in UDP server: {e}")
    
    def run_tcp_server(self):
        """Run the TCP server for file transfers"""
        # Create TCP socket
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.bind(('0.0.0.0', self.port))
        tcp_socket.listen(5)
        
        while True:
            try:
                client_socket, client_address = tcp_socket.accept()
                
                # Handle connection in a separate thread
                threading.Thread(
                    target=self.handle_tcp_connection,
                    args=(client_socket, client_address)
                ).start()
                
            except Exception as e:
                print(f"Error in TCP server: {e}")
    
    def handle_udp_message(self, data, client_address, udp_socket):
        """Handle incoming UDP messages"""
        try:
            message = json.loads(data.decode('utf-8'))
            command = message.get('command')
            request_id = message.get('request_id', str(uuid.uuid4()))
            username = message.get('username', 'Unknown')
            is_verification = message.get('verification', False)  # Check if this is a verification request
            
            # Check request cache to avoid reprocessing
            with self.request_cache_lock:
                if request_id in self.request_cache:
                    cached_response = self.request_cache[request_id]['response']
                    # Send the cached response for duplicated requests
                    self._send_udp_response(cached_response, client_address, udp_socket, request_id)
                    return
            
            # Start with a response skeleton
            response = {'status': 'error', 'message': 'Unknown command error'}
            
            # Handle authentication
            if command == 'check_username':
                print("Client authenticating")
                response = self.handle_check_username(message)
            elif command == 'login':
                response = self.handle_login(message)
                if response['status'] == 'success':
                    print(f"{username} successful login")
                else:
                    print("Incorrect password")
            elif command == 'register':
                print("New user")
                response = self.handle_register(message)
                if response['status'] == 'success':
                    print(f"{username} successfully logged in")
            # Thread operations
            elif command == 'create_thread':
                thread_title = message.get('title', 'Unknown')
                response = self.handle_create_thread(message)
                if response['status'] == 'success':
                    print(f"{username} issued CRT command")
                    print(f"Thread {thread_title} created")
                else:
                    print(f"{username} issued CRT command")
                    print(f"Thread {thread_title} exists")
            elif command == 'list_threads':
                # Only log if this is not a verification request
                if not is_verification:
                    print(f"{username} issued LST command")
                response = self.handle_list_threads(message)
            elif command == 'get_thread':
                thread_id = message.get('thread_id', 'Unknown')
                response = self.handle_get_thread(message)
                if response['status'] == 'success':
                    print(f"{username} issued RDT command")
                    print(f"Thread {thread_id} read")
                else:
                    print(f"{username} issued RDT command")
                    print("Incorrect thread specified")
            elif command == 'delete_thread':
                thread_id = message.get('thread_id', 'Unknown')
                response = self.handle_delete_thread(message)
                if response['status'] == 'success':
                    print(f"{username} issued RMV command")
                    print(f"Thread {thread_id} removed")
                else:
                    print(f"{username} issued RMV command")
                    print(f"Thread {thread_id} cannot be removed")
            elif command == 'post_message':
                thread_id = message.get('thread_id', 'Unknown')
                response = self.handle_post_message(message)
                if response['status'] == 'success':
                    print(f"{username} issued MSG command")
                    print(f"Message posted to {thread_id} thread")
                else:
                    print(f"{username} issued MSG command")
                    print(f"Failed to post to {thread_id} thread")
            elif command == 'edit_message':
                thread_id = message.get('thread_id', 'Unknown')
                response = self.handle_edit_message(message)
                if response['status'] == 'success':
                    print(f"{username} issued EDT command")
                    print("Message has been edited")
                else:
                    print(f"{username} issued EDT command")
                    print("Message cannot be edited")
            elif command == 'delete_message':
                thread_id = message.get('thread_id', 'Unknown')
                response = self.handle_delete_message(message)
                if response['status'] == 'success':
                    print(f"{username} issued DLT command")
                    print("Message has been deleted")
                else:
                    print(f"{username} issued DLT command")
                    print("Message cannot be deleted")
            elif command == 'logout':
                print(f"{username} exited")
                print("Waiting for clients")
                response = self.handle_logout(message)
            else:
                response = {'status': 'error', 'message': 'Unknown command'}
            
            # Add request_id to response for client to match request-response
            response['request_id'] = request_id
            
            # Cache the response for potential retransmissions
            with self.request_cache_lock:
                self.request_cache[request_id] = {
                    'response': response,
                    'timestamp': time.time(),
                    'client_address': client_address
                }
            
            # Send response with enhanced reliability
            self._send_udp_response(response, client_address, udp_socket, request_id)
            
        except json.JSONDecodeError:
            error_response = {'status': 'error', 'message': 'Invalid JSON format'}
            udp_socket.sendto(json.dumps(error_response).encode('utf-8'), client_address)
        except Exception as e:
            error_response = {'status': 'error', 'message': str(e)}
            udp_socket.sendto(json.dumps(error_response).encode('utf-8'), client_address)
        
    
    def _send_udp_response(self, response, client_address, udp_socket, request_id):
        """Send UDP response with enhanced reliability mechanisms"""
        # Determine if this is a critical command that needs extra reliability
        command = response.get('command', '')
        is_critical = command in ['login', 'logout', 'register'] or response.get('status') == 'error'
        
        # Encode response once
        response_data = json.dumps(response).encode('utf-8')
        
        # For critical commands, send multiple copies with slight delays
        num_copies = 3 if is_critical else 1
        
        for attempt in range(num_copies):
            try:
                udp_socket.sendto(response_data, client_address)
                if attempt == 0:
                    pass
                else:
                    # Add a small random delay between retransmissions to prevent collision
                    jitter_delay = random.uniform(0.05, 0.2)
                    time.sleep(jitter_delay)
            except Exception as e:
                # Add a brief delay before retry
                time.sleep(0.1)
    
    def run_connection_cleanup(self):
        """Periodically check and clean up stale connections and cached requests"""
        while True:
            try:
                # Sleep first to allow program initialization
                time.sleep(30)
                
                # Clean up request cache
                current_time = time.time()
                expired_keys = []
                
                with self.request_cache_lock:
                    for request_id, cache_data in self.request_cache.items():
                        if current_time - cache_data['timestamp'] > self.request_cache_ttl:
                            expired_keys.append(request_id)
                    
                    # Remove expired entries
                    for key in expired_keys:
                        del self.request_cache[key]
                        
                # No need to print cleanup messages
                
            except Exception as e:
                print(f"Error during connection cleanup: {e}")

    def handle_tcp_connection(self, client_socket, client_address):
        """Handle TCP connection for file transfers"""
        try:
            # Receive operation type and details
            header_data = client_socket.recv(1024)
            header = json.loads(header_data.decode('utf-8'))
            
            operation = header.get('operation')
            username = header.get('username')
            thread_id = header.get('thread_id')
            
            # Authenticate user
            if username not in self.active_users:
                response = {'status': 'error', 'message': 'Authentication required'}
                client_socket.send(json.dumps(response).encode('utf-8'))
                client_socket.close()
                return
            
            if operation == 'upload':
                self.handle_file_upload(client_socket, header)
            elif operation == 'download':
                self.handle_file_download(client_socket, header)
            else:
                response = {'status': 'error', 'message': 'Invalid operation'}
                client_socket.send(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            try:
                response = {'status': 'error', 'message': str(e)}
                client_socket.send(json.dumps(response).encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()
    
    # Authentication handlers
    def handle_check_username(self, message):
        """Handle username existence check"""
        username = message.get('username')
        
        if not username:
            return {'status': 'error', 'message': 'Username required'}
        
        # Check if username is already active
        if username in self.active_users:
            print(f"{username} has already logged in")
            return {'status': 'error', 'message': 'Username already logged in'}
        
        # Check if username exists in credentials
        if username in self.users:
            return {'status': 'exists', 'message': 'Username exists, please enter password'}
        else:
            return {'status': 'new', 'message': 'Username does not exist, please enter password for new account'}
    
    def handle_login(self, message):
        """Handle user login with existing account"""
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}
        
        # Check if username is already active
        if username in self.active_users:
            print(f"{username} has already logged in")
            return {'status': 'error', 'message': 'Username already logged in by another client'}
        
        # Verify password
        if username in self.users and self.users[username] == password:
            self.active_users.add(username)
            return {'status': 'success', 'message': 'Welcome to the forum'}
        else:
            return {'status': 'error', 'message': 'Invalid password'}
    
    def handle_register(self, message):
        """Handle user registration for new account"""
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}
        
        # Check if username is already active
        if username in self.active_users:
            return {'status': 'error', 'message': 'Username already logged in by another client'}
        
        # Check if username already exists
        if username in self.users:
            return {'status': 'error', 'message': 'Username already exists'}
        
        # Save new credentials
        with self.lock:
            if self.save_credentials(username, password):
                self.users[username] = password
                self.active_users.add(username)
                return {'status': 'success', 'message': f'User {username} registered successfully'}
            else:
                return {'status': 'error', 'message': 'Error saving credentials'}
    
    def handle_logout(self, message):
        """Handle user logout"""
        username = message.get('username')
        
        if username in self.active_users:
            self.active_users.remove(username)
        
        return {'status': 'success', 'message': 'Logged out successfully'}
    
    # Thread handlers
    def handle_create_thread(self, message):
        """Handle thread creation"""
        try:
            # Check if message is a JSON object or string
            if isinstance(message, dict):
                username = message.get('username')
                thread_title = message.get('title')
            else:
                # Handle pipe-separated format for backward compatibility
                fields = message.split("|")
                username = fields[1]
                thread_title = fields[2]
            
            # Check if thread title already exists
            if thread_title in self.threads:
                return {"status": "error", "message": "Thread with this title already exists"}
            
            # Create a new thread entry with title as the key
            self.threads[thread_title] = {
                'title': thread_title,
                'creator': username,
                'created_at': time.time(),
                'messages': [],
                'files': []
            }
            
            # Save threads to file
            if self.save_threads():
                return {"status": "success", "message": f"Thread '{thread_title}' created successfully"}
            else:
                # Roll back if save failed
                del self.threads[thread_title]
                return {"status": "error", "message": "Failed to save thread"}
        except Exception as e:
            print(f"Error creating thread: {e}")
            return {"status": "error", "message": "Failed to create thread"}
    
    def handle_list_threads(self, message):
        """Handle listing all threads"""
        try:
            # Convert threads dictionary to list format expected by client
            thread_list = []
            for title, thread_data in self.threads.items():
                thread_list.append({
                    'id': title,  # Use title as ID
                    'title': title,
                    'creator': thread_data.get('creator', 'Unknown'),
                    'message_count': len(thread_data.get('messages', []))
                })
                
            # Sort threads by title
            thread_list.sort(key=lambda x: x['title'])
            
            # Return as JSON response
            return {
                'status': 'success',
                'threads': thread_list
            }
        except Exception as e:
            print(f"Error listing threads: {e}")
            return {'status': 'error', 'message': 'Failed to list threads'}
    
    def handle_get_thread(self, message):
        """Handle request to view a thread"""
        try:
            # Check if message is a JSON object or string
            if isinstance(message, dict):
                username = message.get('username')
                thread_title = message.get('thread_id')  # This is the thread title
            else:
                # Handle pipe-separated format for backward compatibility
                fields = message.split("|")
                username = fields[1]
                thread_title = fields[2]  # This is the thread title
            
            # Check if thread exists
            if thread_title not in self.threads:
                return {"status": "error", "message": "Thread not found"}
            
            thread_data = self.threads[thread_title]
            
            # Return as JSON
            return {
                "status": "success",
                "thread": {
                    "title": thread_title,
                    "creator": thread_data.get('creator', 'Unknown'),
                    "messages": thread_data.get('messages', []),
                    "files": thread_data.get('files', [])
                }
            }
        except Exception as e:
            print(f"Error getting thread: {e}")
            return {"status": "error", "message": f"Failed to retrieve thread: {str(e)}"}
    
    def handle_delete_thread(self, message):
        """Handle thread deletion"""
        try:
            # Check if message is a JSON object or string
            if isinstance(message, dict):
                username = message.get('username')
                thread_title = message.get('thread_id')  # This is the thread title
            else:
                # Handle pipe-separated format for backward compatibility
                fields = message.split("|")
                username = fields[1]
                thread_title = fields[2]  # This is the thread title
            
            # Check if thread exists
            if thread_title not in self.threads:
                return {"status": "error", "message": "Thread not found"}
            
            # Check if user is the creator of the thread
            creator = self.threads[thread_title].get('creator')
            if creator != username:
                return {"status": "error", "message": "Only the thread creator can delete this thread"}
            
            # Delete the thread
            with self.lock:
                del self.threads[thread_title]
                self.save_threads()
            
            return {"status": "success", "message": f"Thread '{thread_title}' deleted successfully"}
        except Exception as e:
            print(f"Error deleting thread: {e}")
            return {"status": "error", "message": "Failed to delete thread"}
    
    # Message handlers
    def handle_post_message(self, message):
        """Handle posting a message to a thread"""
        try:
            # Check if message is a JSON object or string
            if isinstance(message, dict):
                username = message.get('username')
                thread_title = message.get('thread_id')  # This is the thread title
                content = message.get('content')
            else:
                # Handle pipe-separated format for backward compatibility
                fields = message.split("|")
                username = fields[1]
                thread_title = fields[2]  # This is the thread title
                content = fields[3]
            
            # Check if thread exists
            if thread_title not in self.threads:
                return {"status": "error", "message": "Thread not found"}
            
            # Create new message
            timestamp = int(time.time())
            message_id = len(self.threads[thread_title]['messages']) + 1
            
            new_message = {
                'id': message_id,
                'author': username,
                'timestamp': timestamp,
                'content': content,
                'edited': False,
                'deleted': False
            }
            
            # Add message to thread
            self.threads[thread_title]['messages'].append(new_message)
            
            # Save threads to file
            if self.save_threads():
                return {"status": "success", "message": "Message posted successfully"}
            else:
                # Roll back if save failed
                self.threads[thread_title]['messages'].pop()
                return {"status": "error", "message": "Failed to save message"}
                
        except Exception as e:
            print(f"Error posting message: {e}")
            return {"status": "error", "message": f"Failed to post message: {str(e)}"}
    
    def handle_edit_message(self, message):
        """Handle editing a message in a thread"""
        try:
            # Check if message is a JSON object or string
            if isinstance(message, dict):
                username = message.get('username')
                thread_title = message.get('thread_id')  # This is the thread title
                msg_id = message.get('message_id')
                new_content = message.get('content')
            else:
                # Handle pipe-separated format for backward compatibility
                fields = message.split("|")
                username = fields[1]
                thread_title = fields[2]
                msg_id = fields[3]
                new_content = fields[4]
            
            # Check if thread exists
            if thread_title not in self.threads:
                return {"status": "error", "message": "Thread not found"}
            
            # Convert message_id to integer if it's a string
            if isinstance(msg_id, str):
                msg_id = int(msg_id)
            
            # Find the message in the thread
            found = False
            for i, msg in enumerate(self.threads[thread_title]['messages']):
                if msg['id'] == msg_id:
                    # Check if user is the author
                    if msg['author'] != username:
                        return {"status": "error", "message": "You can only edit your own messages"}
                    
                    # Update the message content
                    self.threads[thread_title]['messages'][i]['content'] = new_content
                    self.threads[thread_title]['messages'][i]['edited'] = True
                    found = True
                    break
            
            if not found:
                return {"status": "error", "message": "Message not found"}
            
            # Save threads to file
            if self.save_threads():
                return {"status": "success", "message": "Message edited successfully"}
            else:
                return {"status": "error", "message": "Failed to save message changes"}
                
        except Exception as e:
            print(f"Error editing message: {e}")
            return {"status": "error", "message": f"Failed to edit message: {str(e)}"}
    
    def handle_delete_message(self, message):
        """Handle deleting a message from a thread"""
        try:
            # Check if message is a JSON object or string
            if isinstance(message, dict):
                username = message.get('username')
                thread_title = message.get('thread_id')  # This is the thread title
                msg_id = message.get('message_id')
            else:
                # Handle pipe-separated format for backward compatibility
                fields = message.split("|")
                username = fields[1]
                thread_title = fields[2]
                msg_id = fields[3]
            
            # Check if thread exists
            if thread_title not in self.threads:
                return {"status": "error", "message": "Thread not found"}
            
            # Convert message_id to integer if it's a string
            if isinstance(msg_id, str):
                msg_id = int(msg_id)
            
            # Find the message in the thread
            found = False
            message_index = -1
            for i, msg in enumerate(self.threads[thread_title]['messages']):
                if msg['id'] == msg_id:
                    # Check if user is the author or thread creator
                    if msg['author'] != username and self.threads[thread_title]['creator'] != username:
                        return {"status": "error", "message": "Only the message author or thread creator can delete this message"}
                    
                    # Store the index to remove the message
                    message_index = i
                    found = True
                    break
            
            if not found:
                return {"status": "error", "message": "Message not found"}
            
            # Remove the message from the array
            with self.lock:
                # Remove the message completely
                del self.threads[thread_title]['messages'][message_index]
                
                # Save threads to file
                if self.save_threads():
                    return {"status": "success", "message": "Message deleted successfully"}
                else:
                    return {"status": "error", "message": "Failed to save message changes"}
                
        except Exception as e:
            print(f"Error deleting message: {e}")
            return {"status": "error", "message": f"Failed to delete message: {str(e)}"}
    
    # File handlers
    def handle_file_upload(self, client_socket, header):
        """Handle file upload via TCP"""
        username = header.get('username')
        thread_title = header.get('thread_id')  # This is the thread title
        filename = header.get('filename')
        file_size = header.get('file_size', 0)
        expected_checksum = header.get('checksum')
        
        if thread_title not in self.threads:
            response = {'status': 'error', 'message': 'Thread not found'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            return
        
        # Send acknowledgement to start transfer
        response = {'status': 'ready', 'message': 'Ready to receive file'}
        client_socket.send(json.dumps(response).encode('utf-8'))
        
        # Prepare file path
        safe_filename = f"{int(time.time())}_{os.path.basename(filename)}"
        file_path = f"server_data/files/{safe_filename}"
        
        # Receive and save file
        try:
            file_checksum = hashlib.md5()
            with open(file_path, 'wb') as f:
                bytes_received = 0
                
                while bytes_received < file_size:
                    chunk = client_socket.recv(min(4096, file_size - bytes_received))
                    if not chunk:
                        break
                    file_checksum.update(chunk)
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            # Verify checksum if provided
            calculated_checksum = file_checksum.hexdigest()
            if expected_checksum and calculated_checksum != expected_checksum:
                # Checksum mismatch - file corrupted during transfer
                if os.path.exists(file_path):
                    os.remove(file_path)
                response = {'status': 'error', 'message': 'Checksum verification failed. File may be corrupted.'}
                client_socket.send(json.dumps(response).encode('utf-8'))
                return
            
            # Update thread with file information
            with self.lock:
                self.threads[thread_title]['files'].append({
                    'filename': safe_filename,
                    'original_name': filename,
                    'uploader': username,
                    'size': file_size,
                    'upload_time': time.time(),
                    'checksum': calculated_checksum
                })
                self.save_threads()
            
            print(f"{username} issued UPD command")
            print(f"{username} uploaded file {filename} to {thread_title} thread")
            
            response = {'status': 'success', 'message': 'File uploaded successfully', 'checksum': calculated_checksum}
            client_socket.send(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            # Clean up partial file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
            
            response = {'status': 'error', 'message': f'Upload failed: {str(e)}'}
            client_socket.send(json.dumps(response).encode('utf-8'))
    
    def handle_file_download(self, client_socket, header):
        """Handle file download via TCP"""
        username = header.get('username')
        thread_title = header.get('thread_id')  # This is the thread title
        filename = header.get('filename')
        
        if thread_title not in self.threads:
            response = {'status': 'error', 'message': 'Thread not found'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            print(f"{username} issued DWN command")
            print(f"Thread {thread_title} does not exist")
            return
        
        # Find file in thread
        file_info = None
        for file in self.threads[thread_title]['files']:
            if file['filename'] == filename or file['original_name'] == filename:
                file_info = file
                break
        
        if not file_info:
            response = {'status': 'error', 'message': 'File not found'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            print(f"{username} issued DWN command")
            print(f"{filename} does not exist in Thread")
            print(f"{thread_title}")
            return
        
        file_path = f"server_data/files/{file_info['filename']}"
        
        if not os.path.exists(file_path):
            response = {'status': 'error', 'message': 'File not found on server'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            return
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Calculate file checksum
        file_checksum = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                file_checksum.update(chunk)
        checksum_hex = file_checksum.hexdigest()
        
        # Send file info with checksum
        response = {
            'status': 'ready',
            'file_size': file_size,
            'original_name': file_info['original_name'],
            'checksum': checksum_hex
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        
        # Wait for client to acknowledge
        ack = client_socket.recv(1024)
        ack_data = json.loads(ack.decode('utf-8'))
        
        if ack_data.get('status') != 'ready':
            return
        
        # Send file
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(4096)
                while chunk:
                    client_socket.send(chunk)
                    chunk = f.read(4096)
            
            print(f"{username} issued DWN command")
            print(f"{filename} downloaded from Thread")
            print(f"{thread_title}")
        except Exception as e:
            print(f"Error sending file: {e}")

    def get_thread_file_path(self, thread_title):
        """Get the file path for a thread"""
        # Ensure thread_title is valid for a filename
        safe_title = thread_title.replace(" ", "_")
        return os.path.join("server_data", safe_title + ".txt")
    
    def thread_exists(self, thread_title):
        """Check if a thread exists"""
        thread_file = self.get_thread_file_path(thread_title)
        return os.path.exists(thread_file)
    
    def get_thread_creator(self, thread_title):
        """Get the creator of a thread"""
        thread_file = self.get_thread_file_path(thread_title)
        try:
            with open(thread_file, "r") as f:
                first_line = f.readline().strip()
                parts = first_line.split("|")
                if len(parts) >= 1:
                    return parts[0]
        except Exception as e:
            print(f"Error getting thread creator: {e}")
        return None
    
    def get_thread_messages(self, thread_title):
        """Get formatted messages from a thread"""
        thread_file = self.get_thread_file_path(thread_title)
        messages = []
        
        try:
            with open(thread_file, "r") as f:
                lines = f.readlines()
                
                # Skip the first line (creator info)
                for i, line in enumerate(lines[1:], 1):
                    parts = line.strip().split("|")
                    if len(parts) >= 3:
                        author = parts[0]
                        timestamp = int(parts[1])
                        content = parts[2]
                        
                        # Format timestamp for display
                        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                        
                        if author == "DELETED":
                            messages.append(f"[{i}] [DELETED] {time_str}: {content}")
                        else:
                            messages.append(f"[{i}] {author} {time_str}: {content}")
        except Exception as e:
            print(f"Error getting thread messages: {e}")
            
        return messages

    def handle_client(self, conn, addr):
        """Handle client connection"""
        try:
            print(f"Client connected from {addr}")
            
            # Receive data from client
            data = conn.recv(4096).decode('utf-8')
            
            if not data:
                return
            
            # Process client request
            response = self.process_client_request(data)
            
            # Send response back to client
            if isinstance(response, dict):
                conn.send(json.dumps(response).encode('utf-8'))
            else:
                conn.send(response.encode('utf-8'))
            
        except Exception as e:
            print(f"Error handling client: {e}")
            error_response = json.dumps({"status": "error", "message": str(e)})
            conn.send(error_response.encode('utf-8'))
        finally:
            conn.close()
            
    def process_client_request(self, data):
        """Process client request and return appropriate response"""
        try:
            command_parts = data.split("|")
            command = command_parts[0].strip()
            # Handle different commands
            if command == "CRT":
                return self.handle_create_thread(data)
            elif command == "LST":
                return self.handle_list_threads(data)
            elif command == "MSG":
                return self.handle_post_message(data)
            elif command == "DLT":
                return self.handle_delete_message(data)
            elif command == "RDT":
                return self.handle_get_thread(data)
            elif command == "EDT":
                return self.handle_edit_message(data)
            elif command == "DEL":
                return self.handle_delete_thread(data)
            else:
                return {"status": "error", "message": "Unknown command"}
        except Exception as e:
            print(f"Error processing request: {e}")
            return {"status": "error", "message": "Invalid request format"}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python server.py <port>")
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
        server = ForumServer(port)
        server.start()
    except ValueError:
        print("Port must be a number")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)