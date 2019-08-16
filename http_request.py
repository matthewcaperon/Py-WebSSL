import requests
import json
from http import HTTPStatus


class HttpRequest:

    def __init__(self, debug):
        self.debug = debug

    def http_post_json(self, url, payload):

        if self.debug:
            print("WebSSL Request URL : " + url)
            print("WebSSL Request Payload:")
            print(payload)

        headers = {'Content-Type': 'application/json', 'Connection': 'close'}

        response = requests.request('POST', url, headers=headers, data=payload, allow_redirects=False, timeout=5)

        if response.status_code != HTTPStatus.OK:
            raise ValueError("HTTP response code: " + str(response.status_code))

        if self.debug:
            print("WebSSL Response:")
            print(json.dumps(json.loads(response.text), indent=4, sort_keys=True))

        return response

    def http_get(self, url):

        if self.debug:
            print("WebSSL Request URL : " + url)

        response = requests.get(url, headers={'Connection': 'close'})

        if response.status_code != HTTPStatus.OK:
            raise ValueError("HTTP response code: " + str(response.status_code))

        if self.debug:
            print("WebSSL Response:")
            print(json.dumps(json.loads(response.text), indent=4, sort_keys=True))

        return response
