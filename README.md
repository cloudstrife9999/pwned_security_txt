# Do pwned websites take security seriously?

Disclosure e-mails from breached websites often have an opening statement regarding how seriously the website takes the security of its users' data. Is that the case, or pure PR talk? Let's find out.

## Context

See <https://twitter.com/troyhunt/status/1682982538409828354>.

## How to run the script

```bash
user@machine ~ $ chmod 700 main.py
user@machine ~ $ ./main.py
```

## Goals

* To check whether pwned websites have `security.txt` file in the `.well-known` directory.
* To check whether the aforementioned `security.txt` file contains a line including `Contact:\s*<valid_contact>` (or `Contact\s+<valid_contact>`).
* To check whether the response containing the aforementioned `security.txt` file has a `Content-Type: text/plain; charset=utf-8` header.
* Alternatively, to check whether the response containing the aforementioned `security.txt` file has a `Content-Type: text/plain` header.

## Methodology

* We send a request to <https://haveibeenpwned.com/api/v3/breaches> in order to get a list of pwned websites.
* We map the list of pwned websites to a list of their domain names.
* We filter out empty and duplicated domain names.
* We setup a web crawler with a request timeout of 30 seconds, and the following custom request headers (in order to simulate a user navigating to a website):

```python
self.__request_headers: dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
```

* We send a `GET /.well-known/security.txt` request to each domain name with HTTPS while attempting to validate the certificate. We allow redirects.
* If a request fails, we try again while ignoring the certificate. We allow redirects.
* If a request fails again, we try with plain HTTP. We allow redirects.
* If at least one of the above requests succeeds, we get the response code, the response body, and the `Content-Type` header.
* Depending on the response code, we either check or not the response body.
* If the response code is `200`, we check the response body for a line including `Contact:\s*<valid_contact>` (or `Contact\s+<valid_contact>`).
* If the request did not fail, we also check whether the `Content-Type` header is compliant with the specification (i.e., `text/plain; charset=utf-8`), or at the very least the suboptimal `text/plain`. If the header is not present, we consider it both non-compliant and suboptimal.
* Depending on the response code, response body, and `Content-Type` header, we either consider the website to have a valid `security.txt` file, or not, or we explicitly say we don't know.

## How to interpret the results

* All the websites that have a valid `security.txt` file in the `.well-known` directory have their domain name listed in `with_security_file.json`. Valid means that the file contains a line including `Contact:\s*<valid_contact>` (or `Contact\s+<valid_contact>`). As explained in [Methodology](#methodology), we first try with HTTPS validating the server certificate, then with HTTPS ignoring the server certificate, and finally with HTTP. While the fallbacks are deninitely insecure, we are mostly interested in `security.txt`. Redirects are allowed.

* All the websites that explicilty return `404` in response to `GET /.well-known/security.txt` have their domain name listed in `without_security_file.json`. As explained in [Methodology], we first try with HTTPS validating the server certificate, then with HTTPS ignoring the server certificate, and finally with HTTP. While the fallbacks are deninitely insecure, we are mostly interested in `security.txt`. Redirects are allowed.

* All websites that do not fall into the above categories have their domain name listed in `unknown.json`. Those websites either do not respond to `GET /.well-known/security.txt` at all, or cause connection errors even with all the fallbacks, or return 200, but do not include a valid `security.txt` file in the response. Redirects are allowed.

* Regardless of which file a domain ends up in, we also record the scheme used for the successul request or the last attempted fallback (i.e., `https://` or `http://`), and whether the server certificate was validated (i.e., `True` or `False`), and also the `Content-Type` header. If it is not present or the request timed out, we record `N/A`.

* If a domain name is listed in `with_security_file.json` or `without_security_file.json`, we also record whether the `Content-Type` header is compliant with the specification (i.e., `text/plain; charset=utf-8`), or at the very least the suboptimal `text/plain`. If the header is not present, we consider it both non-compliant and suboptimal.

## Acknowledgements

* [Troy](https://www.troyhunt.com) [Hunt](https://twitter.com/troyhunt) for the idea.
* [Have I Been Pwned](https://haveibeenpwned.com/) for the pwned domains data.
* [The creators](https://securitytxt.org/) of the `security.txt` specification.
