# WebCD

A Content Discovery tool for finding more interesting/hidden content on web applications.

- [Disclaimers](https://github.com/WillIWas123/WebCD#disclaimers)
- [Why](https://github.com/WillIWas123/WebCD#usecases)
- [Help](https://github.com/WillIWas123/WebCD#example-usage)

## Disclaimers

- This is considered to be a beta release, and may contain bugs and unintentional behavior. Consider yourself warned!
- I've borrowed and tweaked wordlists from [SecLists](https://github.com/danielmiessler/SecLists).


## Why

Why create another content discovery tool when so many already exists?

Most (not all) content discovery tools rely solely on status codes for determining which endpoints "exists". I've seen a lot of applications that have different content on endpoints but return the same status code for multiple, or all endpoints. Relying only on the status code is a poor strategy resulting in subpar output. [HTTPDiff](https://github.com/WillIWas123/HTTPDiff) analyzes all parts of the response; the status code, reason, headers, body, response times, errors, etc., this allows to find some interesting endpoints impossible to find with traditional tools, or even manually.

WebCD uses [HTTPDiff](https://github.com/WillIWas123/HTTPDiff) to determine the normal behavior of an application and checks for any differences when scanning for endpoints. This way it is possible to find endpoints based on any change of behavior, not only limited to the status code!

\* This is one of many tools to come!

## Help

```
python3 webcd.py -h

usage: WebCD [-h] [-e EXTENSIONS [EXTENSIONS ...]] [-fw FILE_WORDLIST] [-dw DIRECTORY_WORDLIST]
             [-sw SPECIAL_WORDLIST] [--recursion RECURSION] (-u URL | -r REQUEST) [-t THREADS] [-p PROXY]
             [-m METHOD] [--header HEADER [HEADER ...]] [-b BODY] [--https] [--verify] [-ar] [-v] [-d] [-s SLEEP]
             [-cs CALIBRATION_SLEEP] [--timeout TIMEOUT] [-ie] [--no-analyze-all]
             [--num-calibrations NUM_CALIBRATIONS]

A Content Discovery tool for finding more interesting/hidden content on web applications

options:
  -h, --help            show this help message and exit
  -e EXTENSIONS [EXTENSIONS ...], --extensions EXTENSIONS [EXTENSIONS ...]
  -fw FILE_WORDLIST, --file-wordlist FILE_WORDLIST
                        Specify wordlist to scan for filenames (extensions will be appended to all filenames)
  -dw DIRECTORY_WORDLIST, --directory-wordlist DIRECTORY_WORDLIST
                        Specify directories to scan for ("/" will be appended to all directory names)
  -sw SPECIAL_WORDLIST, --special-wordlist SPECIAL_WORDLIST
                        Specify special filenames and directories to scan for (no extension will be appended)
  --recursion RECURSION

target:
  -u URL, --url URL
  -r REQUEST, --request REQUEST, --req REQUEST
                        Specify a file containing a raw request for scanning

request:
  -t THREADS, --threads THREADS
  -p PROXY, --proxy PROXY
  -m METHOD, --method METHOD
  --header HEADER [HEADER ...]
  -b BODY, --body BODY  Specify content to be in the body of the request
  --https, --tls
  --verify              Verify SSL certificates
  -ar, --allow-redirects
                        Specify if requests should follow redirects

verbosisty:
  -v, --verbose
  -d, --debug

scan:
  -s SLEEP, -ss SLEEP, --sleep SLEEP
                        Determines how long (ms) the scanner should sleep between each request during scan
  -cs CALIBRATION_SLEEP, --calibration-sleep CALIBRATION_SLEEP
                        Determines how long (ms) the scanner should sleep between each request while calibrating
  --timeout TIMEOUT     Determines the timeout duration (s) for each request
  -ie, --ignore-errors  Ignore errors if any errors occurs during calibration

analyzer:
  --no-analyze-all      Make analyzer skip analyzing the body if the content length is static
  --num-calibrations NUM_CALIBRATIONS
                        Specify how many requests should be sent during calibration
```
