How does the program work?
===========================
Without getting too much on to the why (there are a couple of those at the bottom)
or how it evolved, on its current version, the model looks like this:

* The main function on the scrapper.py file parses the parameter (from now on _initial url_,
_threads_, and _cookies_). 

* It creates an instance of URL (models/models.py) with the _initial url_. This class
was designed to deal with URLs, provided sane comparisons between them and reconstruct
them in case they were relative URLs.

* It creates an instance of the WebIO class (utils/utils.py) letting it know 
about the _cookies_. This instance will handle absolutely all communications with the web.
There's only one instance of this class going around.

* It creates as many threads as _threads_ were passed. The threads are all instances
of the Worker class (scrapper.py). The Worker instances all share the FIFO queue
where the inital_url lives and a set of already visited websites. They also have 
as an attribute the URL of the _initial url_. This is so each thread can create
its own instance of a DBManager (persistence/db_manager.py), which needs to know
to which table name to write.

* The threads will forever try to execute the Worker.check_website_for_xss method,
getting the target URL from the FIFO queue and blocking if there are none. It the url
is not found on the visited_websites set, the Worker will add the URL to the set and
process it.

* The threads processing mostly depends on ScrappedWebsite and XSSDetector (models/models.py).

** The thread will create an instance of a ScrappedWebsite, which parses 
the website with beautifulsoup and has methods prepared to return a list of found 
links on the website (as URL objects) and a list of exposed inputs on the website,
specifing their method, action url, is_upload and their query name. This is used
later by the XSSDetector to test the website.

** After the initial scrapping is done, the Worker threads passes the scrapped_website and the WebIO
instance to the XSSDetector. Then it calls the detect method, which uses the information
from ScrappedWebsite.get_exposed_inputs to create different URLs to attack. 
Each URL is given every payload found on the corresponding xss_test file, as
specified on the README.md file. The correct file to be read from is infered
from the method and is_upload values. After creating the URLs, the XSSDetector will use 
the WebIO to send a request to that precise URL with the correct method, and, if
the response was between 200 and 300 (accepted), the Detector will consider an XSS to be found.
It will return a list of XSSObjects (containing url, payload and method as attributes) to the Worker.

* The worker takes the spotlight again: it locks (because sqlite3 doesn't like being written to by many 
threads at the same time) and sends the list of found xss to its intance of the DBManager, which
safely (_rollback if there was an exception_) writes the changes to the persistence/xss.db under
tablename _initial url_.

* The process starts again, until _every_ URL on the Queue gets marked as 'done'. The URL is marked
as done if there was an exception while processing or if the processing finished. Then the program finishes.

Interesting problems faced
==========================

## When are two URLs the same?
Although it may seem like a trivial problem at first, one quickly realizes 
one may have to take an arbitrary decision here, and there's no perfect option.

The safest option seems to be to request the hole webpage and compare its contents
with another. If the contests are the same, then it is the same URL. But what if you give
the script a quickly-updated website, like lanacion.com? It will say that lanacion.com
and lanacion.com are different if they are visited in an interval of maybe two minutes.

Here the decision was taken to just compare network location, path and query. If those
are the same for two URLs, then the URLs are the same. It is probably not perfect.
The good news? It is easily adjustable: just change the \_\_eq\_\_ and \_\_hash\_\_ methods
on the URL class :).

## When is the program finished?

Again, seeminly trivial problem. 

One is tempted to say that the program is finished when there are no more 
elements on the FIFO queue. If our list of 'to process websites' is done, 
that must mean there are no more websites to process, right?

The thing is this leads to an interesting race condition:
Thread 1 --> pop initial URL and starts to process it...
Thread 2 --> hey, no URL to process! i'm finished! 
Thread 1 --> hey, thread 2, here are the link of the first URL... hey! thread 2!??!?!?!

So that option is out. Keep in mind this most obviously happend with initial url,
but it could potentially happen at any point in the execution.

So the program uses the awesome Queue.task_done() method. For every object put
into the Queue, Queue.task_done() must be called. This works because now
the interaction between threads looks like this: 
Thread 1 --> pop initial URL and start to process it...
Thread 2 --> hey, no URL to process. I'll just wait here 'cause I'm a nice guy
Thread 1 --> hey, thread 2, here are the new url to process 
Thread 2 --> i'll get right at it boss!
Thread 1 --> well, this task is done, onto the next

## How to test for every xss and not miss any?

This one doesn't seem trivial at all. In fact, I couldn't find a correct way
to do it: there are just so many possible tests and ways into which you could
find an XSS, it seems dificult to replicate them all. Actually, the set of 
possible inputs the program tries is very limited  (see _Why...?_ section, last question).

Paliatives for the problem?
* Let user write and add its own tests very easily: this is easily done by the user,
just writing lines into the correct files on the xss_test folder as specified on the README.md
* If the server accepts a request with a problematic payload, then the server is vulnerable. 
It does not mater if it sanitizes the output or hides it from the user. 

This last decision is specially important, because it is what enabled the program to check
for, for example, stored XSS. Take this case:

* Upload a file on http://example.com/A.
* File is stored and shown on http://example.com/C

If we checked for the response CONTENTS, we would never find the stored XSS,
because when uploading in A, the inmediate response is not http://example.com/C.

But if we check the status code, we see that the server accepted the upload.
Fine enough for me: xss found. In case the server sanitized the response or similar,
a human inspecting the vulnerability can surely surpass that.

Why...?
=======

## Why is the whole main worker loop try/excepted so generally?

No unhandled exception should arise while in the loop. The most problematic
part by far is that of WebIO, and Connection exceptions are already handled 
gracefully by the class. The DBManager is also a problem, but there's a try/except
implicit in the `with connection` bit of its code.

Nevertheless, in case something _does_ happend, the try/except in the main loop
will allow the thread to survive and continue doing its work with the next website.
If we didn't try/except everything, if a minor problem arises which results in an exception,
the thread would be DEAD for ever, and that is not nice.

Instead, is just better to log it and continue.

## Why doesn't the script try all possible combinations of inputs to find an XSS? 

Ah, you mean, if the script finds input A and B, why doesn't it try to send 3 malicious payloads,
each looking like (A=payload, B=None), (A=None, B=payload), (A=payload, B=payload)?

While that _could_ expose more XSS, it is computationally very expensive. For a page with N inputs,
we would have to send #(P(N)-1) requests, where P is the powerset of the set of forms and # the cardinal function.
That is (2\*\*N-1).

That means that for a webpage of 16 inputs (not crazy for a registration page, for example) we would have
to make 65535 requests. For a webpage of 32 inputs (unlikely, but not impossible), 4294967295 requests would 
be made.

That's why the program chooses to send one request per form, like this: (A=payload, B=None), (A=None, B=payload). 
While this may be missing some XSS (for example, if filling the two forms returns an error which uses one of the payloads),
this was chosen to make N requests.

## Why does the script visit both http://example.com?param=2 and http://example.com?param=3?

This was designed to be so. Take the case of these two Gruyere pages: 

https://google-gruyere.appspot.com/201813828985/snippets.gtl?uid=brie
https://google-gruyere.appspot.com/201813828985/snippets.gtl?uid=cheddar

Although they only differ on their query, the expose _very_ different results: one
may be vulnerable and the other may not.

## Why doesn't the script visit both http://example.com#1 and http://example.com#2?

This was designed to be so. The fragmeter generally does not lead to a different page,
but to a different part of the same page. No need to visit it twice.

## Why doesn't the script anything on the terminal?

It speed up the execution of the script. Printing is generally slow and 
in a program like this wouldn't be of much help. You do have the logs
if you'd like to see them, though.

It's worth nothing that exceptions (which hopefully never ocurr) will be printed. 
