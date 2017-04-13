# PTNotes
Simple tool for taking notes in a pentest. PTNotes uses data from imported Nessus and Nmap files along with the built-in attack data to build a list of hosts, open ports, and potential attack vectors. It then allows you to add notes to each host and each attack vector. You can then view all attack notes or all host notes at one time. PTNotes allows you to create a separate project for each penetration test.

## Installation
`git clone https://github.com/averagesecurityguy/ptnotes`

or

```
wget https://github.com/averagesecurityguy/ptnotes/archive/<version>.zip
gunzip <version>.zip
```

## Usage

From the ptnotes folder run `./server` then connect to the server on http://127.0.0.1:5000. For security purposes, the server runs on local host by default. If you need to collaborate with other users, you can run PTNotes on a central server and create SSH tunnels to the server. If that is not an option, you must configure the Flask server to run with HTTPS to secure the data in transit. Use the following syntax to create an SSH tunnel to the server:

```
ssh -L 5000:127.0.0.1:5000 <username>@<ssh_server>
```

You can then connect to the PTNotes server on http://127.0.0.1:5000.

## Prerequisites
You will need to install the flask framework: `pip install flask`
