import scanning as scan
import argparse
import sys

### MAIN MENU FILE###

parser = argparse.ArgumentParser(description="A program to perform actions including scanning devices and network, ... Called cyberdeck because of the possibility of carrying quickhacks with you in cyberpunk 2077.")

### SCANNING OPTIONS ###
parser.add_argument("-S", "--scan", help="Perform a scan of device's ports using different protocols and approaches, a device's operational system or scanning your current network for other devices.", action="store_true")

#scan types
parser.add_argument("-Ss", "--synscan", help="Perform a SYN scan of device's ports. Excellent for stealth scanning, but may not be as reliable as a full TCP scan.", action="store_true")
parser.add_argument("-Us", "--udpscan", help="Perform a UDP scan of device's ports. Good for discovering services that may not respond to TCP scans, but can be slower and less reliable. But using the targeted flag, more reliable by sending specific payloads, instead of a general one.", action="store_true")
parser.add_argument("-Ts", "--tcpscan", help="Perform a TCP scan of device's ports. Reliable and thorough, but may be more easily detected by intrusion detection systems.", action="store_true")
parser.add_argument("-Os", "--osdetect", help="Perform an OS detection scan on the target device. This can help identify the operating system and version of the device, which can be useful for identifying vulnerabilities and potential attack vectors.", action="store_true")
parser.add_argument("-Ns", "--networkscan", help="Perform a network scan to discover other devices on the same network. This can find MAC addresses, IP addresses, and other information about the devices on the network. This can be useful for identifying potential targets for further scanning or attacks.", action="store_true")

#scan specific options
parser.add_argument("-t", "--target", help="Specify the target device or network to scan. Must be an IP address")
parser.add_argument("-s", "--stealthiness", default=2, help="Set the stealthiness of the scan. 1 is the slowest, 4 is the fastest. Default is 2.", type=int)
parser.add_argument("-pr", "--portrange", default=1024, help="Set the port range for the scan. Default is 1024. Should be 1024 or 65535. In case of UDP targeted scan, this will be overridden.", type=int)
parser.add_argument("-it", "--istargeted", help="For UDP scans, specify if the scan is targeted. If it is, that means the scan will be more reliable by sending specific payloads, instead of a general one. Default is False.", action="store_true")
parser.add_argument("-sc", "--showclosed", help="Shows closed ports, by default it shows only open ports on the output. This can pollute the output according to the amount of scanned ports. Can only work with SYN, TCP or UDP scan.", action="store_true")

######


args = parser.parse_args()
    
print(r"""
   ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███  ▓█████▄ ▓█████  ▄████▄   ██ ▄█▀
  ▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒▒██▀ ██▌▓█   ▀ ▒██▀ ▀█   ██▄█▒ 
  ▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒░██   █▌▒███   ▒▓█    ▄ ▓███▄░ 
  ▒▓▓▄ ▄██▒░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ░▓█▄   ▌▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ 
  ▒ ▓███▀ ░░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒░▒████▓ ░▒████▒▒ ▓███▀ ░▒██▒ █▄
  ░ ░▒ ▒  ░ ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒
    ░  ▒  ▓██ ░▒░ ▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░ ░ ▒  ▒  ░ ░  ░  ░  ▒   ░ ░▒ ▒░
  ░       ▒ ▒ ░░   ░    ░    ░     ░░   ░  ░ ░  ░    ░   ░        ░ ░░ ░ 
  ░ ░     ░ ░      ░         ░  ░   ░        ░       ░  ░░ ░      ░  ░   
  ░       ░ ░           ░                  ░             ░               
  """)
print()

if len(sys.argv) > 1:

    if args.scan:

        if args.target is None and (args.synscan or args.udpscan or args.tcpscan or args.osdetect):
            parser.error("Target is required for SYN scan, UDP scan, TCP scan, and OS detection.")

        elif args.portrange not in [1024, 65535]:
            parser.error("Port range must be either 1024 or 65535.")

        elif args.istargeted and not args.udpscan:
            parser.error("The '--istargeted' option can only be used with the '--udpscan' option.")

        elif args.stealthiness not in [1, 2, 3, 4]:
            parser.error("Stealthiness must be an integer between 1 and 4.")

        elif args.showclosed and (args.osdetect or args.networkscan):
            parser.error("Closed ports can be only shown in a UDP, SYN or TCP scan.")
        else: 
            
            if args.synscan:
                scan.parsing_scanoptions("syn", destination_ip=args.target, scan_quietness=args.stealthiness, targeted_ports=args.portrange, showClosed=args.showclosed)
            if args.udpscan:
                scan.parsing_scanoptions("udp", destination_ip=args.target, targeted_ports=args.portrange, isTargeted=args.istargeted, scan_quietness=args.stealthiness, showClosed=args.showclosed)
            if args.tcpscan:
                scan.parsing_scanoptions("tcp", destination_ip=args.target, scan_quietness=args.stealthiness, targeted_ports=args.portrange, showClosed=args.showclosed)
            if args.osdetect:
                scan.parsing_scanoptions("os", destination_ip=args.target)
            if args.networkscan:
                scan.parsing_scanoptions("net")

else: 
    #as more functionalities will be added, more options will be available here
    print("\n Choose your quickhack:\n\nh. Help\nq. Quit\n1. Scanning\n") 

    if __name__ == "__main__":
        choice = input("Enter your choice: ")
        print()
        if choice == "h":
            print("Help: Choose an option to perform a quickhack." \
            "\n1. Scanning: Includes port scanning, operational system detection and network scan.")
        elif choice == "1":
            scan.scanmenu()
        elif choice == "q":
            print("Quitting...")
        elif choice == "09142026": 
            print("I was indeed pushed that day.")
        else:
            print("Invalid choice. Please try again.")