# PTNotes
Simple tool for taking notes in a pentest. PTNotes uses data from imported Nessus and Nmap files along with the built-in attack data to build a list of hosts, open ports, and potential attack vectors. It then allows you to add notes to each host and each attack vector. You can then view all attack notes or all host notes at one time. PTNotes allows you to create a separate project for each penetration test.

## Prerequisites
You will need to install the flask framework: `pip install flask`

## Installation
`git clone https://github.com/averagesecurityguy/ptnotes`

or

```
wget https://github.com/averagesecurityguy/ptnotes/archive/<version>.zip
gunzip <version>.zip
```

## Supported Versions
The only supported versions of PTNotes is the latest release and the dev branch. All other releases are obsolete and will be routinely removed from Github.


## Usage
From the ptnotes folder run `./server` then connect to the server on http://127.0.0.1:5000. For security purposes, the server runs on local host by default. If you need to collaborate with other users, you can run PTNotes on a central server and create SSH tunnels to the server. If that is not an option, you must configure the Flask server to run with HTTPS to secure the data in transit. Use the following syntax to create an SSH tunnel to the server:

```
ssh -L 5000:127.0.0.1:5000 <username>@<ssh_server>
```

You can then connect to the PTNotes server on http://127.0.0.1:5000.

## Creating New Attacks
To add new attacks to PTNotes edit the `data/attacks.json` file. Each attack uses the following structure:

```
{
    "name": "SMB Brute-force.",
    "description": "Attempt to brute-force the local administrator account on these SMB servers.",
    "keywords": ["--smb-os-discovery--", "--11011--"]
}
```

An attack needs a name and description along with a list of keywords that signify a machine may vulnerable to the attack. When data is imported to PTNotes the Nessus plugin id or the Nmap script name are extracted along with the plugin/script output. You can search for vulnerabilities using the plugin id or script name surrounded by -- as seen in the example above. You can also use any text from the plugin or script output. Multiple keywords are joined with OR to create the final query.

## To use the Docker container
Start by building it:
```
docker build . -t <your username>/ptnotes
```
Next, run it:
```
docker run -d -p 5000:5000 --name=ptnotes -v <absolute path to the repo>/data:/ptnotes/data <your username>/ptnotes
```
Destroy it when you're done (your data will persist since you used the volume mount parameter):
```
docker stop ptnotes && docker rm ptnotes
```
