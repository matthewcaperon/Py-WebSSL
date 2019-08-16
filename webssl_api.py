import json
import base64
from http_request import HttpRequest


class WebSSLApi:

    webssl_get_status = 'https://c1.cloudhsms.com/hsm/status'
    webssl_get_info = 'https://c1.cloudhsms.com/hsm/info'
    webssl_gen_key_url = 'https://c1.cloudhsms.com/genpkey'
    webssl_ecies_encrypt_url = 'https://c1.cloudhsms.com/ecies/encrypt'
    webssl_ecies_decrypt_url = 'https://c1.cloudhsms.com/ecies/decrypt'
    webssl_cms_encrypt_url = 'https://c1.cloudhsms.com/cms/encrypt'
    webssl_cms_decrypt_url = 'https://c1.cloudhsms.com/cms/decrypt'
    webssl_cms_sign_url = 'https://c1.cloudhsms.com/cms/sign'
    webssl_cms_verify_url = 'https://c1.cloudhsms.com/cms/verify'
    webssl_cms_encrypt_sign_url = 'https://c1.cloudhsms.com/cms/encryptSign'
    webssl_cms_verify_decrypt_url = 'https://c1.cloudhsms.com/cms/verifyDecrypt'
    webssl_cms_sign_encrypt_url = 'https://c1.cloudhsms.com/cms/signEncrypt'
    webssl_cms_decrypt_verify_url = 'https://c1.cloudhsms.com/cms/decryptVerify'
    webssl_req_generate_csr_url = 'https://c1.cloudhsms.com/req/generateCsr'
    webssl_req_generate_key_and_cert_url = 'https://c1.cloudhsms.com/req/generateKeyCert'
    webssl_x509_sign_csr_url = 'https://c1.cloudhsms.com/x509/signCsr'

    def __init__(self, debug):
        self.http = HttpRequest(debug)

    def get_info(self):

        response = self.http.http_get(self.webssl_get_info)

        json_data = json.loads(response.text)

        hsm_id = json_data['id']
        hsm_type = json_data['type']

        return hsm_id, hsm_type

    def get_status(self):

        response = self.http.http_get(self.webssl_get_status)

        json_data = json.loads(response.text)

        bat_voltage = json_data['batteryVoltage']
        temp = json_data['temperature']
        free_mem = json_data['freeMemory']
        used_mem = json_data['usedMemory']

        return bat_voltage, temp, free_mem, used_mem

    def generate_key(self, algorithm):

        payload = json.dumps({'algorithm': algorithm})

        response = self.http.http_post_json(self.webssl_gen_key_url, payload)

        json_data = json.loads(response.text)
        private_key = json_data['privateKey']
        public_key = json_data['publicKey']

        return public_key, private_key

    def ecies_encrypt(self, public_key, data_to_encrypt):

        data_to_encrypt_b64 = base64.b64encode(data_to_encrypt)

        payload = json.dumps({'algorithm': 'ecies-kdf2-dh-aes128-sha256',
                              'in': str(data_to_encrypt_b64, 'utf-8'),
                              'inKey': public_key})

        response = self.http.http_post_json(self.webssl_ecies_encrypt_url, payload)

        json_data = json.loads(response.text)
        ecies = json_data['ecies']

        return ecies

    def ecies_decrypt(self, private_key, ecies_pem):

        payload = json.dumps({'algorithm': 'ecies-kdf2-dh-aes128-sha256',
                              'in': ecies_pem,
                              'inKey': private_key})

        response = self.http.http_post_json(self.webssl_ecies_decrypt_url, payload)

        json_data = json.loads(response.text)
        data_b64 = json_data['data']

        data = str(base64.b64decode(str.encode(data_b64)), 'utf-8')

        return data

    def cms_encrypt(self, recipients_certificate, data_to_encrypt):

        data_to_encrypt_b64 = base64.b64encode(data_to_encrypt)

        payload = json.dumps({'recip': recipients_certificate, 'in': str(data_to_encrypt_b64, 'utf-8')})

        response = self.http.http_post_json(self.webssl_cms_encrypt_url, payload)

        json_data = json.loads(response.text)
        cms = json_data['cms']

        return cms

    def cms_decrypt(self, private_key, ecies_to_decrypt):

        payload = json.dumps({'in': str(ecies_to_decrypt, 'utf-8'), 'inKey': private_key})

        response = self.http.http_post_json(self.webssl_cms_decrypt_url, payload)

        json_data = json.loads(response.text)
        data_b64 = json_data['data']

        data = str(base64.b64decode(str.encode(data_b64)), 'utf-8')

        return data

    def cms_sign(self, signer_certificate, private_key, data_to_sign):

        data_to_sign_b64 = base64.b64encode(data_to_sign)

        payload = json.dumps({'signer': signer_certificate, 'in': str(data_to_sign_b64, 'utf-8'), 'inKey': private_key})

        response = self.http.http_post_json(self.webssl_cms_sign_url, payload)

        json_data = json.loads(response.text)
        cms = json_data['cms']

        return cms

    def cms_verify(self, cms_to_verify):

        payload = json.dumps({'in': cms_to_verify})

        response = self.http.http_post_json(self.webssl_cms_verify_url, payload)

        json_data = json.loads(response.text)
        is_verified = json_data['verified']

        return is_verified

    def cms_encrypt_and_sign(self, signer_certificate, recipient_certificate, private_key, data):

        data_b64 = base64.b64encode(data)

        payload = json.dumps({'signer': signer_certificate, 'recip': recipient_certificate,
                              'in': str(data_b64, 'utf-8'), 'inKey': private_key})

        response = self.http.http_post_json(self.webssl_cms_encrypt_sign_url, payload)

        json_data = json.loads(response.text)
        cms = json_data['cms']

        return cms

    def cms_verify_and_decrypt(self, private_key, data):

        payload = json.dumps({'in': data, 'inKey': private_key})

        response = self.http.http_post_json(self.webssl_cms_verify_decrypt_url, payload)

        json_data = json.loads(response.text)
        is_verified = json_data['verified']
        data_b64 = json_data['data']

        data = str(base64.b64decode(str.encode(data_b64)), 'utf-8')

        return is_verified, data

    def cms_sign_and_encrypt(self, signer_certificate, recipient_certificate, private_key, data):

        data_b64 = base64.b64encode(data)

        payload = json.dumps({'signer': signer_certificate, 'recip': recipient_certificate,
                              'in': str(data_b64, 'utf-8'), 'inKey': private_key})

        response = self.http.http_post_json(self.webssl_cms_sign_encrypt_url, payload)

        json_data = json.loads(response.text)
        cms = json_data['cms']

        return cms

    def cms_decrypt_and_verify(self, private_key, data):

        payload = json.dumps({'in': data, 'inKey': private_key})

        response = self.http.http_post_json(self.webssl_cms_decrypt_verify_url, payload)

        json_data = json.loads(response.text)
        data_b64 = json_data['data']

        is_verified = json_data['verified']
        data = str(base64.b64decode(str.encode(data_b64)), 'utf-8')

        return is_verified, data

    def req_generate_csr(self, private_key, common_name, country, state, locality,
                         organisation, organisational_unit, email):

        dn = {'commonName': common_name}
        if country is not None:
            dn['country'] = country
        if state is not None:
            dn['state'] = state
        if locality is not None:
            dn['locality'] = locality
        if organisation is not None:
            dn['organisation'] = organisation
        if organisational_unit is not None:
            dn['organisational_unit'] = organisational_unit
        if email is not None:
            dn['email'] = email

        payload = json.dumps({'inKey': private_key, 'digest': 'sha-256', 'distinguishedNames': dn})

        response = self.http.http_post_json(self.webssl_req_generate_csr_url, payload)

        json_data = json.loads(response.text)
        csr = json_data['csr']

        return csr

    def req_generate_key_and_cert(self, algorithm, common_name, country, state, locality,
                                  organisation, organisational_unit, email, days, subject_type):

        dn = {'commonName': common_name}
        if country is not None:
            dn['country'] = country
        if state is not None:
            dn['state'] = state
        if locality is not None:
            dn['locality'] = locality
        if organisation is not None:
            dn['organisation'] = organisation
        if organisational_unit is not None:
            dn['organisational_unit'] = organisational_unit
        if email is not None:
            dn['email'] = email

        payload = json.dumps({'algorithm': algorithm, 'days': str(days), 'digest': 'sha-256',
                              'subjectType': subject_type, 'distinguishedNames': dn})

        response = self.http.http_post_json(self.webssl_req_generate_key_and_cert_url, payload)

        json_data = json.loads(response.text)
        private_key = json_data['privateKey']
        certificate = json_data['certificate']

        return private_key, certificate

    def x509_sign_csr(self, private_key, signer_certificate, csr, days):

        payload = json.dumps({'inKey': private_key, 'signerCert': signer_certificate, 'csr': csr,
                              'days': str(days), 'digest': 'sha-256'})

        response = self.http.http_post_json(self.webssl_x509_sign_csr_url, payload)

        json_data = json.loads(response.text)
        certificate = json_data['certificate']

        return certificate
