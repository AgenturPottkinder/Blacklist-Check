DNS Check for given IPv4, IPv6 and Hostname
===

This small go script checks a lot of DNS Servers for Blacklisting. It can be easily deployed and adjusted.

**Details:**


* You are able to run this script with only IPv4, IPv4 and Hostname or IPv4, IPv6 and Hostname. Only by Hostname, IPv6 or only IPv4 and IPv6 is not yet possible.
* The script returns statusCode 0 if no found was given and 1 if at least on blacklist problem was found

Requirements
---

In order to run this script you just need to install go lang. For more information see https://golang.org/doc/install 

Installation
---

* In order to install this please clone this repository to a location you like.
* On a normal linux just run ```./build.sh```
* You now have a binary named server in the ```./bin``` directory.

Run this script
---

In order to run this script you just need to run ```./bin/server IPv4 [HostName] [IPv6]```

Known Todo
---

* Make all paramters optional
* Move DNS List to a YAML File

Support and supporting
---

There is no free support for this script. If you need help open a ticket and wait for response, if you need paid support write us a mail.

In order to support this script please do pull request or buy paid support.
Supporting OpenSource is always nice to help receiving public scripts for everyone.

It would be great if you'd be able to provide more DNS Lists, help with documentation that is missing or just help with maintaining this list.

How to report bugs
---

If you want to report bugs please ensure to give the following information:

* git branch is master and latest version
* when did you compile the ```server``` binary?
* a copy of your config file WITHOUT PASSWORD would be nice
* What is the expected output?
* What is happening?
* Is the IP in your log the correct public ip?

CopyRight and Law Stuff
---

This script is free to use and modify for anyone. If you use this script you accept that you are using this script on your own risk. It would be nice if you'd fork publicly and do pull requests in order to update this script.

Created in 2017 from Bastian Bringenberg <bastian@agentur-pottkinder.de>
