import os
import subprocess

password = "super_secret_password"
api_key = "123456789"

user_input = input("Enter command: ")

eval(user_input)

os.system("ls")

subprocess.run(["echo", "hello"])