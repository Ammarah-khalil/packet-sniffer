Packet Sniffer with GUI
A Python-based Packet Sniffer designed to capture and analyze network traffic in real time.
The project uses Scapy for packet capturing and a Tkinter-based GUI for user-friendly interaction.

Features
Captures live network packets (TCP, UDP, ICMP, and more).

Displays source IP, destination IP, protocol, and packet length.

Start/Stop capture functionality.

Save captured packets to a .pcap file for further analysis in Wireshark.

Clean and simple GUI interface.

Project Structure

packet-sniffer/
│
├── gui_sniffer.py       # Main Python script with GUI
├── sniffer_core.py      # Core packet capture logic
└── README.md            # Project documentation
Installation & Setup
1. Clone the Repository

git clone git@github.com:Ammarah-khalil/packet-sniffer.git
cd packet-sniffer
2. (Optional) Create Virtual Environment

python3 -m venv venv
source venv/bin/activate    # Linux/Mac
venv\Scripts\activate       # Windows
3. Install Dependencies

pip install -r requirements.txt
Usage
Run the Packet Sniffer

sudo python3 gui_sniffer.py
Note: Root/sudo privileges are required on Linux to capture packets.

Future Improvements
Add filtering options (by IP, protocol, or port).

Export captured data in CSV/JSON.

Add multi-threading for better real-time performance.

Author
Ammarah Khalil
Cybersecurity Student | Network Security Enthusiast
GitHub Profile

License
This project is licensed under the MIT License.
