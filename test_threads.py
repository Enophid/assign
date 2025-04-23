import os
import json

def clear_threads_file():
    """Clear the threads.json file by writing an empty object"""
    try:
        with open("server_data/threads.json", "w") as f:
            json.dump({}, f)
        print("Successfully cleared threads.json")
    except Exception as e:
        print(f"Error clearing threads.json: {e}")

def check_threads_file():
    """Check if threads.json exists and what its content is"""
    if os.path.exists("server_data/threads.json"):
        try:
            with open("server_data/threads.json", "r") as f:
                content = json.load(f)
            print(f"threads.json exists with content: {json.dumps(content, indent=2)}")
        except Exception as e:
            print(f"Error reading threads.json: {e}")
    else:
        print("threads.json does not exist")

if __name__ == "__main__":
    print("=== Before clearing ===")
    check_threads_file()
    
    print("\n=== Clearing threads file ===")
    clear_threads_file()
    
    print("\n=== After clearing ===")
    check_threads_file() 