import argparse, sys
from threading import BoundedSemaphore


class ParseHeaders(argparse.Action):
    """
    Parsing headers from cli arguments
    """

    def __call__(self, parser, namespace, values, option_string=None):
        d = getattr(namespace, self.dest) or {}
        if values:
            for item in values:
                split_items = item.split(":", 1)
                key = split_items[0].strip()
                value = split_items[1]
                d[key] = value.strip()
        setattr(namespace, self.dest, d)


class Options:
    """
    Adds multiple options for how the scanner should behave
    """

    def __init__(self):
        self.args = None
        self.get_args()
        self.lock = BoundedSemaphore(self.args.threads)

    def get_args(self):
        parser = argparse.ArgumentParser(
            prog="WebCD",
            description="A Content Discovery tool for finding more interesting/hidden content on web applications",
        )
        parser.add_argument(
            "-e",
            "--extensions",
            default=["", ".php", ".asp", ".aspx", ".html", ".jsp", ".htm"],
            nargs="+",
        )
        parser.add_argument(
            "-fw",
            "--file-wordlist",
            default=f"{'/'.join(__file__.split('/')[:-1])}/cd.txt",
            help="Specify wordlist to scan for filenames (extensions will be appended to all filenames)",
        )
        parser.add_argument(
            "-dw",
            "--directory-wordlist",
            default=f"{'/'.join(__file__.split('/')[:-1])}/cd_dir.txt",
            help='Specify directories to scan for ("/" will be appended to all directory names)',
        )
        parser.add_argument(
            "-sw",
            "--special-wordlist",
            default=f"{'/'.join(__file__.split('/')[:-1])}/cd_special.txt",
            help="Specify special filenames and directories to scan for (no extension will be appended)",
        )
        parser.add_argument("--recursion", type=int, default=0)

        target_parser = parser.add_argument_group("target")
        target_parser_2 = target_parser.add_mutually_exclusive_group(required=True)
        target_parser_2.add_argument("-u", "--url")
        target_parser_2.add_argument("-r", "--request", "--req", help="Specify a file containing a raw request for scanning")

        request_parser = parser.add_argument_group("request")
        request_parser.add_argument("-t", "--threads", default=10, type=int)
        request_parser.add_argument("-p", "--proxy")
        request_parser.add_argument("-m", "--method", default="GET")
        request_parser.add_argument("--header", nargs="+", action=ParseHeaders, default={})
        request_parser.add_argument("-b", "--body", default="", help="Specify content to be in the body of the request")
        request_parser.add_argument("--https", "--tls", action="store_true", default=False)
        request_parser.add_argument("--verify", default=False, action="store_true", help="Verify SSL certificates")
        request_parser.add_argument(
            "-ar", "--allow-redirects", default=False, action="store_true", help="Specify if requests should follow redirects"
        )
        # Waiting for urllib3 to release http 2 support
        # request_parser.add_argument("--version", default="HTTP/2")

        verbosity_parser = parser.add_argument_group("verbosisty")
        verbosity_parser.add_argument("-v", "--verbose", action="store_true", default=False)
        verbosity_parser.add_argument("-d", "--debug", action="store_true", default=False)

        scan_parser = parser.add_argument_group("scan")
        scan_parser.add_argument(
            "-s",
            "-ss",
            "--sleep",
            default=0,
            type=int,
            help="Determines how long (ms) the scanner should sleep between each request during scan",
        )
        scan_parser.add_argument(
            "-cs",
            "--calibration-sleep",
            default=0,
            type=int,
            help="Determines how long (ms) the scanner should sleep between each request while calibrating",
        )
        scan_parser.add_argument("--timeout", type=int, default=8, help="Determines the timeout duration (s) for each request")
        scan_parser.add_argument(
            "-ie",
            "--ignore-errors",
            default=False,
            action="store_true",
            help="Ignore errors if any errors occurs during calibration",
        )

        analyzer_parser = parser.add_argument_group("analyzer")
        analyzer_parser.add_argument(
            "--no-analyze-all",
            action="store_false",
            default=True,
            help="Make analyzer skip analyzing the body if the content length is static",
        )
        analyzer_parser.add_argument(
            "--num-calibrations", type=int, default=4, help="Specify how many requests should be sent during calibration"
        )
        analyzer_parser.add_argument(
            "--num-verifications", type=int, default=3, help="Specify how many times an endpoint should be verified/re-tested"
        )

        self.args = parser.parse_args()
        self.set_args()

    def parse_request(self):
        """
        Reads a request from file and parses it to be used when sending requests.
        """
        # TODO: open in bytes mode, need to change other stuff to make this work though
        with open(self.args.request, "r") as f:
            data = f.read()

        splitted = data.split(" ")
        setattr(self.args, "method", splitted[0])

        path = splitted[1]  # Path and query
        # version = splitted[2].split("\n")[0]
        # setattr(self.args, "version", version)

        c = 0
        body = False
        body_value = ""
        headers = {}
        for i in data.split("\n"):
            if c == 0:
                c += 1
                continue

            if not i:
                body = True
                continue

            if not body:
                splitted = i.split(":")
                name = splitted[0]
                value = splitted[1]
                headers[name] = value.strip()
            elif body:
                body_value += i + "\n"

        body_value = body_value[:-1]
        setattr(self.args, "body", body_value)
        setattr(self.args, "header", headers)

        host = headers.get("Host") or headers.get("host")
        if not host and not self.args.url:
            print('Need to specify either "Host" header or URL!')
            sys.exit(1)

        if self.args.url:
            setattr(self.args, "url", url)
        else:
            scheme = "http"
            if self.args.https:
                scheme = "https"
            setattr(self.args, "url", f"{scheme}://{host}{path}")

    def set_args(self):
        """
        Used for processing misc options.
        """
        if self.args.request:
            self.parse_request()
        if self.args.debug:
            setattr(self.args, "verbose", True)
