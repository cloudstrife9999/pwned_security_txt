#!/usr/bin/env python3

from multiprocessing.pool import Pool
from requests import get, Response
from json import dump
from typing import cast, TypeAlias


DataClasses: TypeAlias = dict[int, str]
PwnedDomain: TypeAlias = dict[str, int | str | bool | DataClasses]
Result: TypeAlias = dict[str, str | bool | int]


class SecurityChecker():
    def __init__(self) -> None:
        self.__with_security_file: list[Result] = []
        self.__without_security_file: list[Result] = []
        self.__unknown: list[Result] = []
        self.__template: Result = {
            "ID": -1,
            "domain": "",
            "security_file_explicitly_not_found": False,
            "content_is_valid_security_file": False,
            "content_type_header": "",
            "compliant_content_type_header": False,
            "suboptimal_content_type_header": False,
            "scheme": "",
            "verified_certificate": False,
        }
        # We want to simulate a user typing the relevant URL into their web browser.
        self.__request_headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        self.__request_timeout_in_seconds: int = 30
        self.__https_scheme: str = "https://"

    def __get_pwned_domains(self) -> list[PwnedDomain]:
        try:
            api_endpoint = "https://haveibeenpwned.com/api/v3/breaches"

            response: Response = get(url=api_endpoint, headers=self.__request_headers, timeout=self.__request_timeout_in_seconds)

            if response.status_code != 200:
                raise IOError("Error while fetching data from the HIBP API.")
            else:
                return response.json()
        except IOError as e:
            raise e
        except Exception as ex:
            raise IOError("An unknown error occurred while fetching data from the HIBP API.") from ex

    def check_for_security_file(self, domain: str, scheme: str = "https://", verify: bool = True) -> Result:
        print(f"Checking {domain} with {scheme} and {'' if verify else 'NOT '}validating the server certificate...")

        try:
            response: Response = get(url=scheme + domain + "/.well-known/security.txt", allow_redirects=True, verify=verify, timeout=self.__request_timeout_in_seconds, headers=self.__request_headers)

            return self.__parse_response(domain=domain, response=response, verify=verify, scheme=scheme)
        except Exception:
            if verify:
                return self.check_for_security_file(domain=domain, verify=False)
            elif scheme == self.__https_scheme:
                return self.check_for_security_file(domain=domain, scheme="http://", verify=False)
            else:
                response_template: Result = self.__template.copy()

                response_template["domain"] = domain
                response_template["scheme"] = scheme
                response_template["verified_certificate"] = verify
                response_template["content_type_header"] = "N/A"

                return response_template

    def __parse_response(self, domain: str, response: Response, verify: bool, scheme: str) -> Result:
        response_template: Result = self.__template.copy()

        response_template["domain"] = domain
        response_template["scheme"] = scheme
        response_template["verified_certificate"] = verify
        response_template["content_type_header"] = response.headers["content-type"] if "content-type" in response.headers else "N/A"
        response_template["compliant_content_type_header"] = "content-type" in response.headers and str(response.headers["content-type"]).rstrip().replace("\n", "").replace("\r", "") == "text/plain; charset=utf-8"
        response_template["suboptimal_content_type_header"] = "content-type" in response.headers and str(response.headers["content-type"]).rstrip().replace("\n", "").replace("\r", "") == "text/plain"

        if response.status_code == 404:
            response_template["security_file_explicitly_not_found"] = True
        elif response.status_code == 200:
            response_template["content_is_valid_security_file"] = self.__validate_security_file_content(response=response)

        return response_template

    def __validate_security_file_content(self, response: Response) -> bool:
        lines: list[str] = [line.strip() for line in response.text.replace("\n\r", "\n").replace("\r", "\n").split("\n")]

        return len(lines) > 0 and any([self.__valid_contact_line(line=line) for line in lines])

    def __valid_contact_line(self, line: str) -> bool:
        if line.startswith("Contact:"):
            line = line.replace("Contact:", "").strip()

            return len(line) > 0 and (self.__https_scheme in line or ("mailto:" in line and "@" in line))
        elif line.startswith("Contact "):
            line = line.replace("Contact", "").strip()

            return len(line) > 0 and (self.__https_scheme in line or ("mailto:" in line and "@" in line))
        else:
            return False

    def __store_results(self) -> None:
        with open("with_security_file.json", "w") as f:
            dump(obj=self.__with_security_file, fp=f, indent=4)

        with open("without_security_file.json", "w") as f:
            dump(obj=self.__without_security_file, fp=f, indent=4)

        with open("unknown.json", "w") as f:
            dump(obj=self.__unknown, fp=f, indent=4)

    def __append_result(self, result: Result, collection: list[Result]) -> None:
        result["ID"] = len(collection) + 1

        collection.append(result)

    def __classify_results(self, results: list[Result]) -> None:
        for result in results:
            if result["security_file_explicitly_not_found"]:
                self.__append_result(result=result, collection=self.__without_security_file)
            elif result["content_is_valid_security_file"]:
                self.__append_result(result=result, collection=self.__with_security_file)
            else:
                self.__append_result(result=result, collection=self.__unknown)

    def check(self) -> None:
        pwned_domains_data: list[PwnedDomain] = self.__get_pwned_domains()

        # Get all domain names as strings, then filter out those that are empty strings, then remove duplicates.
        pwned_domains: set[str] = set(filter(lambda domain: len(domain) > 0, map(lambda data: cast(str, data["Domain"]), pwned_domains_data)))

        pool: Pool = Pool(processes=20)
        results: list[Result] = pool.map(func=self.check_for_security_file, iterable=pwned_domains)

        self.__classify_results(results=results)
        self.__store_results()  


if __name__ == "__main__":
    checker: SecurityChecker = SecurityChecker()

    checker.check()
