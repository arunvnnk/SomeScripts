#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  indiahouselogin.py
#  
#  Copyright 2014 arun <arun@arun-laptop>
#
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

#Just a little something that I wrote to automate internet login through the firewall at my residence.
#The script sends an initial request to any address and the firewall returns a standard login page
#The script parses the page to extract the value of a hidden field and sends the post request with user-name and password and the hidden
#field

#To-do-take as parameters the connection name/UUID and then trigger only if a specific connection is up/or take different
#parameters for different connections

#TO USE, replace username and password on line 69 and Copy the script to /etc/network/if-up.d to execute at a connection up
#It is a fortinet firewall, for other simple devices,can use BeautifulSoup to extract the value from the login page

import string, os, sys
import httplib,urllib2,urllib
from bs4 import BeautifulSoup
import requests
import sys
from subprocess import call

def get_header():
	headers = {
    'Host': 'google.com',
    'Connection': 'keep-alive',
    'Origin': 'http://google.com',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1',
    'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
    'Referer': 'http://google.com',
    'Accept-Encoding': 'gzip,deflate,sdch',
    'Accept-Language': 'en-US,en;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
	}
	return headers

def extract_magic():
	req = urllib2.Request('http://google.com')
	response = urllib2.urlopen(req)
	the_page = response.read()
	soup = BeautifulSoup(the_page)
	l=[tag.attrs for tag in soup.findAll('input')]
	return l[1]['value']

def main():
	magic_value=extract_magic()
	data = {"4Tredir": "/","magic":magic_value,"username":"","password":""}
	data = urllib.urlencode(data) 
	extract_magic()
	req = urllib2.Request('http://google.com', data,get_header()) 
	response = urllib2.urlopen(req)
	the_page = response.read()
	return 0

if __name__ == '__main__':
	main()

