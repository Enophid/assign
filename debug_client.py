import json

def test_list_threads():
    print("=== Testing Thread Listing ===")
    
    # Simulate an empty thread list response from server
    server_response = {
        'status': 'success',
        'threads': [],
        'request_id': '123'
    }
    
    print(f"Server response: {json.dumps(server_response)}")
    
    # Now simulate client processing the response
    if server_response['status'] == 'success':
        threads = server_response.get('threads', [])
        
        # Check if there are any threads
        if not threads:
            print("No threads available")
        else:
            print("\nAvailable Threads:")
            print("-" * 50)
            for thread in threads:
                print(f"ID: {thread['id']} | Title: {thread['title']} | Creator: {thread['creator']} | Messages: {thread['message_count']}")
            print("-" * 50)
    else:
        print(f"Failed to list threads: {server_response['message']}")
    
    # Now manually add a thread and see what happens
    print("\n=== Testing with manually added thread ===")
    
    # Add a test thread - this simulates potential hardcoded data
    test_thread = {
        'id': 1,
        'title': '3331',
        'creator': 'yoda',
        'message_count': 0
    }
    
    manual_response = {
        'status': 'success',
        'threads': [test_thread],
        'request_id': '124'
    }
    
    print(f"Manual response: {json.dumps(manual_response)}")
    
    # Now simulate client processing the response
    if manual_response['status'] == 'success':
        threads = manual_response.get('threads', [])
        
        # Check if there are any threads
        if not threads:
            print("No threads available")
        else:
            print("\nAvailable Threads:")
            print("-" * 50)
            for thread in threads:
                print(f"ID: {thread['id']} | Title: {thread['title']} | Creator: {thread['creator']} | Messages: {thread['message_count']}")
            print("-" * 50)
    else:
        print(f"Failed to list threads: {manual_response['message']}")

if __name__ == "__main__":
    test_list_threads() 