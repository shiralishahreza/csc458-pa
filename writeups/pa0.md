Programming Assignment 0 Writeup
====================

My name: Grace Leung

My UTORID : 1006268067

I collaborated with: No one

I would like to credit/thank these classmates for their help: None except all those who created and commented on Piazza.

This programming assignment took me about 10 hours to do.

My public ip address output from webget was: 138.51.85.105

- Optional: I had unexpected difficulty with: I originally included the extra line break all in one string (i.e., "\r\n \r\n) which did not work and caused my write call to block my read call but I thought my read call was at fault. I also did not think the problem was my write call because when I printed the request it displayed properly with the line break and the write_count increased by one. It wasn't until I tried sending the commands one by one that I realized it wasn't interpreting the extra line break correctly the first time.

- Optional: I think you could make this lab better by: Perhaps using a different function name for "get_URL".

- Optional: I was surprised by: In the tutorial for pa0, I asked about what the "get_URL" function was for because I didn't use it. I thought it was a getter to be used in our code later on (something like return host + path) and I wrote my code under the call to the "get_URL" instead.

- Optional: I'm not sure about: I noticed that the parameters use string reference variables and string view as opposed to string (which I used), I just assume it is cast when it is passed in as an argument but I am slightly unsure about it. I also don't understand why the the request cannot include "\r\n \r\n" but I assume maybe whitespace was trimmed.