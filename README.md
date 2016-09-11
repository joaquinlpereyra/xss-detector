XSS-Scanner
===========
Take an URL and test it with user defined payloads for XSS. Then recursively do the same 
for every link found inside that URL which points to the same domain.

Installation
============
A modern Unix system is asumed. You will need sqlite3 and python 3.5. 

You also need the following dependencies for python:
    *requests: to make requests and get their response
    *dataset: for connecting and writing to the sqlite3 database.
    *BeautifoulSoup4: for scrapping the website. 

All of these can be easily installed with pip:
```
pip install -r requirements.txt
```

Or, package by package...
```
pip install --user requests dataset beautifulsoup4
```

Or, with docker...
```
$ docker build -t scanner
```

And then you can start it with 
```
$ docker run scanner 
```

Usage 
=====
Before doing anything, you probably want to populate the xss_test folders with your
own tests. There are a couple ones included, though, so you may try the program as is.

The 'common' file is for tests valid for both get and post requests. One payload for line.
The 'get_method' is only used for get requests. One payload for line.
The 'post_method' is only used for post requests. One payload for line.
The upload_test folder contains file which you want to try to upload if an upload option is found.

If the payloads are accepted by the server (response code is between 200 and 300), the program
will consider an XSS to be found. Importantly, the program doesn't check for sanitization:
a site is considered vulnerable if the payload was accepted, even if the payload may have been
sanitized. Chances are that if the server didn't outright block it, you can find a way to surpass
the sanitization. 

You must provide the initial URL (an URI is not enough) and the amount of threads
to be used. You can optionally provide cookies as a json string.

The results will be stored in the database named xss.db on the persistence folder.
The table name is the *exactly* the URL provided in the parameters.

There is also a log found on logs/logs.log

```
$ python scanner.py --help

positional arguments:
  initial_url        The seed URL (NOT URI) for the program.
  threads            Amount of threads to be used.

optional arguments:
  -h, --help         show this help message and exit
  --cookies COOKIES  You can specify cookies to be used in the requests. You
                     must provide it as a json which lools like this:
                     '{"cookie1": "value1", "cookie2": "value2", ...}
```

Example
=======

To scan the Gruyere project with 4 threads and some made-up cookies:
```
python scanner.py https://google-gruyere.appspot.com/201813828985/ 4 --cookies '{"mycookie": "myvalue"}'
```

Thats assuming python3 is the default python binary of your system. If that doesn't work,
try using 'python3' instead of 'python'
