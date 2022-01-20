#!/bin/python3

import requests


def request(url):
	try:
		return requests.get("http://" + url)
	except requests.exceptions.ConnectionError:
			pass
target_url = input("[*] Enter Target URL:")
			
file = open("common.txt", "r")
for line in file:
				word = line.strip()
				full_url = target_url + "/" + word
				response = request(full_url)
				if response:
					print("[+] Discovered Directory at this link: " + full_url)
		


