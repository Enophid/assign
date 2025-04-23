# Discussion Forum Application

This is a command-line discussion forum application that allows users to create and manage threads, post messages, and share files.

## Features

- User authentication (registration and login)
- Create, list, read, and delete threads
- Post, edit, and delete messages within threads
- Upload and download files to/from threads
- Command-line interface for both client and server

## Communication Protocol

- Most commands use UDP for communication
- File uploads and downloads use TCP
- Custom application layer protocol based on JSON messages

## Requirements

- Python 3.6 or higher
- No additional dependencies required (only standard library modules)

## Getting Started

### Server Setup

1. Create a credentials.txt file in the server directory (or it will be created automatically on first run)
   - Format: `username password` (one per line, separated by a space)
   - Example:
     ```
     alice pass123
     bob securepass
     ```

2. Start the server by running:
   ```
   python server.py <port>
   ```
   Where `<port>` is the port number the server will listen on.

3. The server will create the following directory structure for storing data:
   - `server_data/` - Main data directory
   - `server_data/files/` - For uploaded files
   - `server_data/threads.json` - Thread and message data

### Client Setup

1. Start the client by running:
   ```
   python client.py <server_ip> <server_port>
   ```
   Where:
   - `<server_ip>` is the IP address of the server (use 127.0.0.1 for localhost)
   - `<server_port>` is the port number the server is listening on

2. The client will create a `downloads/` directory to store downloaded files.

## Authentication Process

1. The client prompts the user to enter a username
2. The server checks if the username exists in credentials.txt
   - If the username exists, the client prompts for a password and attempts to log in
   - If the username does not exist, the client prompts for a password to create a new account
3. For new accounts, the server adds the username and password to credentials.txt
4. The server prevents multiple clients from logging in with the same username simultaneously

## Client Commands

### Available Commands
- `create <title>` - Create a new thread
- `list` - List all threads
- `read <thread_id>` - Read a thread's messages
- `delete <thread_id>` - Delete a thread
- `post <thread_id> <message>` - Post a message to a thread
- `edit <thread_id> <msg_id> <content>` - Edit a message
- `delete_msg <thread_id> <msg_id>` - Delete a message
- `upload <thread_id> <filepath>` - Upload a file to a thread
- `download <thread_id> <filename>` - Download a file from a thread
- `logout` - Logout from the server
- `help` - Show help message
- `exit` - Exit the application

## Example Usage

### Server Side
```
$ python server.py 12345
Forum server started on port 12345 (UDP+TCP)
UDP server listening on port 12345
TCP server listening on port 12345
```

### Client Side
```
$ python client.py 127.0.0.1 12345
Welcome to the Discussion Forum Client
Type 'help' to see available commands

Enter username: alice
Enter password: 
Welcome alice!

alice> create My First Thread
Thread created successfully (ID: 1)

alice> post 1 Hello everyone!
Message posted successfully

alice> list

Available Threads:
--------------------------------------------------
ID: 1 | Title: My First Thread | Creator: alice | Messages: 1
--------------------------------------------------

alice> read 1

Thread: My First Thread (Created by: alice)
--------------------------------------------------
[0] alice: Hello everyone!
--------------------------------------------------

alice> logout
Logged out successfully

Enter username: 
```

## Implementation Details

### Server
- Multithreaded design to handle multiple clients concurrently
- Authentication based on credentials.txt file
- Separate UDP and TCP servers running on the same port
- Data persistence using JSON files for threads and messages

### Client
- Command-line interface with interactive prompts
- Support for both interactive and direct command usage
- Progress display for file transfers

## Concurrency Support

The server is designed to handle multiple clients concurrently. It uses threading to:
1. Handle UDP messages from different clients simultaneously
2. Process TCP file transfers without blocking other operations
3. Protect shared data structures with locks to prevent race conditions
4. Prevent multiple clients from using the same username simultaneously 