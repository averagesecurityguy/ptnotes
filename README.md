# PTNotes
Simple tool for taking notes in a pentest. PTNotes uses data from imported Nessus and Nmap files along with the built-in attack data to build a list of hosts, open ports, and potential attack vectors. It then allows you to add notes to each host and each attack vector. You can then view all attack notes or all host notes at one time. PTNotes allows you to create a separate project for each penetration test.

## Installation
`git clone https://github.com/averagesecurityguy/ptnotes`

or

```
wget https://github.com/averagesecurityguy/ptnotes/archive/v<version_number>.zip
gunzip v<version_number>.zip
```

## Usage

From the ptnotes folder run `python server` then connect to the server on http://127.0.0.1:5000.

## Prerequisites
You will need to install the flask framework: `pip install flask`
