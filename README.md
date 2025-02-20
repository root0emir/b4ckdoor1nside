# b4ckdoor1nside

## Description

**b4ckdoor1nside** is an penetration testing and security assessment tool. This tool is designed to be used by authorized penetration testers and security researchers to identify vulnerabilities in target systems and assess their security posture. The features of the tool allow for various operations on the target system and provide comprehensive analysis.

## Warning

********************************************************************************
* This tool is intended for ethical and legal purposes only. Usage of this     *
* tool for unauthorized access to systems and networks is prohibited and       *
* punishable by law. The developers and distributors of this tool are not      *
* responsible for any illegal activities carried out using this tool. Please   *
* ensure you have proper authorization before using this tool.                 *
********************************************************************************

! - This tool is intended for ethical hacking and security assessment purposes only, to help identify and rectify vulnerabilities in systems. The developers and distributors are not responsible for any misuse or damage caused by this tool.

## Features

- **User-Friendly Interface:** Prompts the user for the IP address and port number.
- **Automatic Listener Startup:** Automatically starts a listener on the specified port using netcat.
- **Command Execution:** Executes commands on the target system.
- **Directory Change:** Changes the working directory on the target system.
- **File Download:** Downloads files from the target system.
- **File Upload:** Uploads files to the target system.
- **Screenshot Capture:** Captures screenshots of the target system.
- **Keylogger Start:** Starts a keylogger on the target system.
- **Keylogger Dump:** Retrieves keylogger data from the target system.
- **Network Information Retrieval:** Retrieves network information from the target system.
- **Persistence Maintenance:** Ensures persistence on the target system.
- **Encrypted Communication:** Encrypts and decrypts communication using a strong encryption algorithm.
- **System Information Retrieval:** Retrieves hardware and software information from the target system.
- **Process Management:** Lists and terminates processes on the target system.
- **Port Scanning:** Scans open ports on the target system.
- **Network Traffic Monitoring:** Monitors and records network traffic on the target system.
- **User Account Management:** Manages user accounts on the target system.
- **Scheduled Tasks Management:** Creates and manages scheduled tasks on the target system.
- **Log Reading:** Reads system logs on the target system.
- **Registry Editing (Windows):** Edits the registry on Windows target systems.
- **File Searching:** Searches for specific files on the target system.
- **System Shutdown/Restart:** Shuts down or restarts the target system.
- **Screen Recording:** Records the screen on the target system as a video file.
- **Active Network Connections Listing:** Lists active network connections on the target system.
- **Audio Recording:** Records audio from the target system's microphone.
- **Output Logging:** Logs all command outputs locally.
- **File Shredding:** Permanently deletes files on the target system.

## Usage Instructions

### Requirements

- Python 3.x
- Netcat (nc)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/b4ckdoor1nside.git
   cd b4ckdoor1nside
   ```

2. **Install the required dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

### Usage

1. **Attacker Side (Your Machine):**
   - Start a listener. You can use `netcat` for this:
     ```bash
     nc -lvp 12345
     ```
   - The above command will listen for connections on the specified port (12345).

2. **Target System:**
   - Copy the script to the target system and run it:
     ```bash
     python3 b4ckdoor1nside.py
     ```

3. **Check the Connection:**
   - On the listener terminal, you will see the connection from the target system, and you can start sending commands.

### Commands

- `cd <directory>`: Changes the working directory.
- `download <file_path>`: Downloads the specified file.
- `upload <file_name>`: Uploads the specified file.
- `screenshot`: Takes a screenshot.
- `keylogger_start`: Starts the keylogger.
- `keylogger_dump`: Dumps the keylogger data.
- `network_info`: Retrieves network information.
- `persistence`: Ensures persistence.
- `system_info`: Retrieves system information.
- `list_processes`: Lists running processes.
- `kill_process <pid>`: Terminates the specified process.
- `port_scan <target_ip> <port_range>`: Scans the specified IP and port range.
- `network_traffic <interface>`: Monitors traffic on the specified network interface.
- `manage_users <command>`: Manages user accounts.
- `schedule_task <command>`: Creates a scheduled task.
- `read_logs`: Reads system logs.
- `edit_registry <command>`: Edits the registry (Windows).
- `search_files <directory> <file_name>`: Searches for files in the specified directory.
- `shutdown`: Shuts down the system.
- `reboot`: Reboots the system.
- `record_audio <duration>`: Records audio for the specified duration.
- `record_screen <duration>`: Records the screen for the specified duration.
- `list_network_connections`: Lists network connections.
- `shred_file <file_path>`: Permanently deletes the specified file.

### License

**b4ckdoor1nside** is an open-source project licensed under the MIT License. For more information, see the `LICENSE` file.
