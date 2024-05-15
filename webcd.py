from options import Options
from httpdiff import Analyzer, Response

from threading import Thread, BoundedSemaphore, Lock
import random
import time
import string
import requests

import urllib3

urllib3.disable_warnings()
from http.cookiejar import DefaultCookiePolicy


class WebContentDiscovery:
    def __init__(self, options, url=None, recursion=0, locks=None):
        self.options = options
        if locks is None:
            self.calibration_lock = Lock()
            self.threads_lock = BoundedSemaphore(self.options.args.threads)
            self.wg = BoundedSemaphore(self.options.args.threads * 3)
            self.print_lock = Lock()
        else:
            self.calibration_lock, self.threads_lock, self.wg, self.print_lock = locks
        self.session_lock = Lock()
        self.recursion = recursion
        self.recursion_jobs = []
        self.session_count = 0

        self.base_url = url or self.options.args.url
        if "FUZZ" not in self.base_url:
            # Adding "/" at the end of the path, and adding "FUZZ" if it doesn't exist
            path = self.get_path(self.base_url)
            if path[-1] != "/":
                self.base_url = self.set_path(self.base_url, path + "/FUZZ")
            else:
                self.base_url = self.set_path(self.base_url, path + "FUZZ")

        try:
            with open(self.options.args.directory_wordlist) as f:
                self.directory_payloads = f.read()[:-1]
        except Exception:
            self.directory_payloads = None
        try:
            with open(self.options.args.file_wordlist) as f:
                self.file_payloads = f.read()[:-1]
        except Exception:
            self.file_payloads = None
        try:
            with open(self.options.args.special_wordlist) as f:
                self.special_payloads = f.read()[:-1]
        except Exception:
            self.special_payloads = None

        self.allow_redirects = self.options.args.allow_redirects
        self.proxies = {}
        if self.options.args.proxy:
            self.proxies = {"http": self.options.args.proxy, "https": self.options.args.proxy}
        self.verify = self.options.args.verify
        self.headers = self.options.args.header
        self.method = self.options.args.method
        self.sessions = [requests.Session() for i in range(self.options.args.threads)]
        for s in self.sessions:
            s.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        self.body = self.options.args.body

    def add_cachebusters(self, url, headers):
        cachebuster = "".join(random.choices(string.ascii_letters, k=random.randint(3, 15))) + "=1"
        if "?" in url:
            url += "&" + cachebuster
        else:
            url += "?" + cachebuster

        if headers.get("User-Agent") is not None:  # TODO: fix for other headers as well
            headers["User-Agent"] = (
                headers["User-Agent"] + f" {''.join(random.choices(string.ascii_letters,k=random.randint(3,15)))}"
            )
        return url

    def verify_endpoint(self, analyzer, url, filename, ext, key, checks, diffs, rec_check):

        if self.options.args.debug is True:
            self.print_lock.acquire()
            print(f"[INFO] verifying endpoint: {url.replace('FUZZ',filename+ext)}")
            self.print_lock.release()

        response, response_time, error = self.verify_baseline(analyzer, url, ext)
        if response is not None:
            # Baseline has changed
            self.calibration_lock.acquire()
            analyzer.add_response(response, response_time, error)
            self.calibrate_baseline(url, ext, analyzer=analyzer)
            self.calibration_lock.release()
            return self.check_endpoint(analyzer, url, filename, ext, key, checks=checks, release_lock=False, rec_check=rec_check)

        random_value = "".join(random.choices(string.ascii_letters, k=random.randint(3, 15)))
        path = self.get_path(url)
        new_url = self.set_path(url, path.replace("FUZZ", f"{filename}{random_value}{ext}"))
        response, response_time, error = self.send(new_url)

        diffs2 = list(analyzer.is_diff(response, response_time, error))
        if diffs == diffs2:
            return False

        random_value = "".join(random.choices(string.ascii_letters, k=random.randint(3, 15)))
        new_url = self.set_path(url, path.replace("FUZZ", f"{random_value}{filename}{ext}"))
        response, response_time, error = self.send(new_url)
        diffs2 = analyzer.is_diff(response, response_time, error)
        if diffs == diffs2:
            return False

        if checks >= self.options.args.num_verifications:
            path = self.get_path(url)
            new_url = self.set_path(url, path.replace("FUZZ", filename + ext))
            count = 0
            for i in diffs:
                count += len(i)
            output = f"[Endpoint] {new_url}"
            if self.options.args.verbose:
                output += f" {diffs[0][0]} - {count}"
            self.print_lock.acquire()
            print(output)
            self.print_lock.release()

            if len(filename) > 0 and (ext == "/" or filename[-1] == "/"):
                if self.recursion < self.options.args.recursion:
                    job = Thread(
                        target=main,
                        args=(new_url, self.recursion + 1, (self.calibration_lock, self.threads_lock, self.wg, self.print_lock)),
                    )
                    self.recursion_jobs.append(job)

            return True
        return self.check_endpoint(analyzer, url, filename, ext, key, checks=checks + 1, release_lock=False, rec_check=rec_check)

    def check_endpoint(self, analyzer, url, filename, ext, key, checks=0, release_lock=True, rec_check=0):
        # recursion check, if the check_endpoint is called over 100 times for one endpoint check we exit
        if rec_check > 100:
            self.print_lock.acquire()
            print(f"[WARN] Too many recursions for {filename} with extension {ext}")
            self.print_lock.release()
            return False
        result = False
        path = self.get_path(url)
        new_url = self.set_path(url, path.replace("FUZZ", f"{filename}{ext}"))
        response, response_time, error = self.send(new_url)
        diffs = list(analyzer.is_diff(response, response_time, error))
        if len(diffs) > 0:
            result = self.verify_endpoint(analyzer, url, filename, ext, key, checks, diffs, rec_check + 1)

        if release_lock is True:
            self.wg.release()
        return result

    def send(self, url, session=None):
        """
        sends an actual request
        TODO: ensure that cookies aren't added when a Set-Cookie header is returned from server.
        """

        headers = self.headers.copy()
        url = self.add_cachebusters(url, headers)
        response = None
        error = ""
        try:
            if self.options.args.sleep != 0:
                time.sleep(self.options.args.sleep / 1000)
            start = time.time()
            self.threads_lock.acquire()
            if session is None:
                # TODO: consider changing to round robin
                self.session_lock.acquire()
                session = self.sessions[self.session_count]
                self.session_count += 1
                if self.session_count >= self.options.args.threads:
                    self.session_count = 0
                self.session_lock.release()
            response = session.request(
                self.method,
                url,
                headers=headers,
                verify=self.verify,
                proxies=self.proxies,
                timeout=self.options.args.timeout,
                allow_redirects=self.allow_redirects,
                data=self.body,
            )

            response = Response(response)

        except Exception as e:
            error = str(type(e))
            if self.options.args.debug:
                self.print_lock.acquire()
                print(f"ERROR when sending request: {e}")
                self.print_lock.release()
        finally:
            response_time = round((time.time() - start) * 10 ** 3)
            self.threads_lock.release()
        return response, response_time, error

    def verify_baseline(self, analyzer, url, ext):
        random_value = "".join(random.choices(string.ascii_letters, k=random.randint(3, 15)))
        new_url = url.replace("FUZZ", random_value + ext)
        response, response_time, error = self.send(new_url)
        diffs = analyzer.is_diff(response, response_time, error)
        for i in diffs:
            return response, response_time, error
        return None, None, None

    def calibrate_baseline(self, url, ext, analyzer=None):
        if self.options.args.verbose:
            self.print_lock.acquire()
            print(f"[INFO] CALIBRATING {url.replace('FUZZ',ext)}")
            self.print_lock.release()

        if analyzer is None:
            analyzer = Analyzer()
            analyzer.verbose = self.options.args.verbose
            analyzer.analyze_all = not self.options.args.no_analyze_all

        for i in range(self.options.args.num_calibrations):
            random_value = "".join(random.choices(string.ascii_letters, k=random.randint(3, 15)))
            new_url = url.replace("FUZZ", random_value + ext)
            response, response_time, error = self.send(new_url)
            if error and self.options.args.ignore_errors is False:
                return None
            analyzer.add_response(response, response_time, error)
            time.sleep(self.options.args.calibration_sleep or self.options.args.sleep or (10000 - response_time) / 10000)
        response, response_time, error = self.send(new_url)
        if error and self.options.args.ignore_errors is False:
            return None
        analyzer.add_response(response, response_time, error)

        if self.options.args.verbose:
            self.print_lock.acquire()
            print("[INFO] Done calibrating!")
            self.print_lock.release()
        return analyzer

    def get_path(self, url):
        path = "/" + "/".join(url.split("?")[0].split("&")[0].split("#")[0].split("/")[3:])
        return path

    def set_path(self, url, path):
        indexes = {}
        index = url.find("?")
        if index != -1:
            indexes["?"] = index
        index = url.find("&")
        if index != -1:
            indexes["&"] = index
        index = url.find("#")
        if index != -1:
            indexes["#"] = index
        first = "?"
        if len(indexes) > 0:
            first = min(indexes, key=indexes.get)
            url = "/".join(url.split("/")[:3]) + path + first + first.join(url.split(first)[1:])
        else:
            url = "/".join(url.split("/")[:3]) + path
        return url

    def scan_directories(self, url, jobs):
        for i in self.directory_payloads.split("\n"):
            analyzer = None
            path = "/".join(self.get_path(url.replace("FUZZ", i + "/")).split("/")[:-2])
            key = f"{path}//"
            new_url = self.set_path(url, path + "/FUZZ")
            if self.analyzers.get(key) is None:
                self.calibration_lock.acquire()
                if self.analyzers.get(key) is None:
                    analyzer = self.calibrate_baseline(new_url, "/")
                    self.analyzers[key] = analyzer
                self.calibration_lock.release()

            if analyzer is None and self.analyzers.get(key) is None:
                # Some error occured during calibration
                self.print_lock.acquire()
                print(f"[INFO] Skipping rest of directory scanning due to error while calibrating {url}")
                self.print_lock.release()
                return
            self.wg.acquire()

            job = Thread(
                target=self.check_endpoint,
                args=(analyzer or self.analyzers.get(key), url, i, "/", key),
            )
            jobs.append(job)
            job.start()

    def scan_filenames(self, url, jobs):
        for j in self.options.args.extensions:
            for i in self.file_payloads.split("\n"):
                path = "/".join(self.get_path(url.replace("FUZZ", i + j)).split("/")[:-1])
                key = f"{path}/{j}"
                new_url = self.set_path(url, path + "/FUZZ")
                if self.analyzers.get(key) is None:
                    self.calibration_lock.acquire()
                    if self.analyzers.get(key) is None:
                        self.analyzers[key] = self.calibrate_baseline(new_url, j)
                    self.calibration_lock.release()

                if self.analyzers.get(key) is None:
                    # Some error occured during calibration
                    # Consider only skipping the one extension
                    self.print_lock.acquire()
                    print(f"[INFO] Skipping rest of filename scanning due to error while calibrating {url}")
                    self.print_lock.release()
                    return

                self.wg.acquire()
                job = Thread(
                    target=self.check_endpoint,
                    args=(self.analyzers.get(key), url, i, j, key),
                )
                jobs.append(job)
                job.start()

    def scan_specials(self, url, jobs):
        for i in self.special_payloads.split("\n"):
            j = ""
            if "." in i:
                j = "." + ".".join(i.split(".")[1:])
            i = ".".join(i.split(".")[:-1])
            path = "/".join(self.get_path(url.replace("FUZZ", i + j)).split("/")[:-1])
            key = f"{path}/{j}"
            new_url = self.set_path(url, path + "/FUZZ")
            if self.analyzers.get(key) is None:
                self.calibration_lock.acquire()
                if self.analyzers.get(key) is None:
                    self.analyzers[key] = self.calibrate_baseline(new_url, j)
                self.calibration_lock.release()

                if self.analyzers.get(key) is None:
                    # Some error occured during calibration
                    self.print_lock.acquire()
                    print(f"[INFO] Skipping rest of special scanning due to error while calibrating {url}")
                    self.print_lock.release()
                    return

            self.wg.acquire()
            job = Thread(
                target=self.check_endpoint,
                args=(self.analyzers.get(key), url, i, j, key),
            )
            jobs.append(job)
            job.start()

    def scan(self, url=None, recursion=0):
        if url is None:
            url = self.base_url
        self.analyzers = {}
        jobs = []
        self.print_lock.acquire()
        print(f"[INFO] Scanning {url}")
        self.print_lock.release()

        if self.directory_payloads is not None:
            self.scan_directories(url, jobs)
        else:
            self.print_lock.acquire()
            print(f"[INFO] Error opening directory wordlist skipping directory scanning for {url}")
            self.print_lock.release()

        if self.file_payloads is not None:
            self.scan_filenames(url, jobs)
        else:
            self.print_lock.acquire()
            print(f"[INFO] Error opening filename wordlist skipping filename scanning for {url}")
            self.print_lock.release()

        if self.special_payloads is not None:
            self.scan_specials(url, jobs)
        else:
            self.print_lock.acquire()
            print(f"[INFO] Error opening special wordlist skipping special scanning for {url}")
            self.print_lock.release()

        for job in jobs:
            job.join()

        for job in self.recursion_jobs:
            job.start()
            job.join()


def main(url=None, recursion=0, locks=None):
    options = Options()
    webcd = WebContentDiscovery(options, url=url, recursion=recursion, locks=locks)
    webcd.scan()


if __name__ == "__main__":
    main()
