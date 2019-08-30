import json
import base64
from http_request import HttpRequest
from csr_decoder import CSRDecoder
from crt_decoder import CRTDecoder


class Api:
    webssl_base_url = 'https://c1.cloudhsms.com'
    webssl_get_status_url = webssl_base_url + '/hsm/status'
    webssl_get_info_url = webssl_base_url + '/hsm/info'
    webssl_gen_key_url = webssl_base_url + '/genpkey'
    webssl_ecies_encrypt_url = webssl_base_url + '/ecies/encrypt'
    webssl_ecies_decrypt_url = webssl_base_url + '/ecies/decrypt'
    webssl_cms_encrypt_url = webssl_base_url + '/cms/encrypt'
    webssl_cms_decrypt_url = webssl_base_url + '/cms/decrypt'
    webssl_cms_sign_url = webssl_base_url + '/cms/sign'
    webssl_cms_verify_url = webssl_base_url + '/cms/verify'
    webssl_cms_encrypt_sign_url = webssl_base_url + '/cms/encryptSign'
    webssl_cms_verify_decrypt_url = webssl_base_url + '/cms/verifyDecrypt'
    webssl_cms_sign_encrypt_url = webssl_base_url + '/cms/signEncrypt'
    webssl_cms_decrypt_verify_url = webssl_base_url + '/cms/decryptVerify'
    webssl_req_generate_csr_url = webssl_base_url + '/req/generateCsr'
    webssl_req_decode_csr_url = webssl_base_url + '/req/decodeCsr'
    webssl_req_generate_key_and_self_signed_cert_url = webssl_base_url + '/req/generateKeyCert'
    webssl_req_generate_key_and_signed_cert_url = webssl_base_url + '/req/generateKeySignedCert'
    webssl_x509_sign_csr_url = webssl_base_url + '/x509/signCsr'
    webssl_x509_decode_crt_url = webssl_base_url + '/x509/decodeCert'
    webssl_pkcs12_export_url = webssl_base_url + '/pkcs12/exportP12'

    def __init__(self, debug):
        self.http = HttpRequest(debug)

    def get_info(self):

        response = self.http.http_get(self.webssl_get_info_url)

        json_data = json.loads(response.text)

        hsm_id = json_data['id']
        hsm_type = json_data['type']

        return hsm_id, hsm_type

    def get_status(self):

        response = self.http.http_get(self.webssl_get_status_url)

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

    def cms_encrypt(self, algorithm, recipients_certificate, data_to_encrypt):

        data_to_encrypt_b64 = base64.b64encode(data_to_encrypt)

        payload = json.dumps(
            {'algorithm': algorithm, 'recip': recipients_certificate, 'in': str(data_to_encrypt_b64, 'utf-8')})

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

    def cms_sign(self, digest, signer_certificate, private_key, data_to_sign):

        data_to_sign_b64 = base64.b64encode(data_to_sign)

        payload = json.dumps({'digest': digest, 'signer': signer_certificate, 'in': str(data_to_sign_b64, 'utf-8'),
                              'inKey': private_key})

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

    def cms_encrypt_and_sign(self, algorithm, digest, signer_certificate, recipient_certificate, private_key, data):

        data_b64 = base64.b64encode(data)

        payload = json.dumps({'algorithm': algorithm, 'digest': digest,
                              'signer': signer_certificate, 'recip': recipient_certificate,
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

    def cms_sign_and_encrypt(self, algorithm, digest, signer_certificate, recipient_certificate, private_key, data):

        data_b64 = base64.b64encode(data)

        payload = json.dumps({'algorithm': algorithm, 'digest': digest, 'signer': signer_certificate,
                              'recip': recipient_certificate,
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

    def req_generate_csr(self, digest, private_key, common_name, country, state, locality,
                         organisation, organisational_unit, email, domain_component, key_usage_list,
                         extended_key_usage_list, subject_type, path_length, ip, dns):

        request_dict = self._prepare_cert_req(digest, common_name, country, state, locality,
                                              organisation, organisational_unit, email, domain_component,
                                              key_usage_list,
                                              extended_key_usage_list, subject_type, path_length, ip, dns)

        request_dict.update({'inKey': private_key})

        payload = json.dumps(request_dict)

        response = self.http.http_post_json(self.webssl_req_generate_csr_url, payload)

        json_data = json.loads(response.text)
        csr = json_data['csr']

        return csr

    def req_decode_csr(self, csr):

        payload = json.dumps({'csr': csr})

        response = self.http.http_post_json(self.webssl_req_decode_csr_url, payload)

        csr = CSRDecoder.from_json(response.text)

        return csr

    def req_generate_key_and_self_signed_cert(self, algorithm, digest, common_name, country, state, locality,
                                              organisation, organisational_unit, email, domain_component, days,
                                              key_usage_list,
                                              extended_key_usage_list, subject_type, path_length, ip, dns):

        request_dict = self._prepare_cert_req(digest, common_name, country, state, locality,
                                              organisation, organisational_unit, email, domain_component,
                                              key_usage_list,
                                              extended_key_usage_list, subject_type, path_length, ip, dns)

        request_dict.update({'algorithm': algorithm, 'days': str(days)})

        payload = json.dumps(request_dict)

        response = self.http.http_post_json(self.webssl_req_generate_key_and_self_signed_cert_url, payload)

        json_data = json.loads(response.text)
        private_key = json_data['privateKey']
        certificate = json_data['certificate']

        return private_key, certificate

    def req_generate_key_and_signed_cert(self, password, algorithm, digest, signer_certificate, private_key,
                                         common_name, country, state, locality, organisation, organisational_unit,
                                         email, domain_component, days, key_usage_list, extended_key_usage_list,
                                         subject_type, path_length, ip, dns):

        request_dict = self._prepare_cert_req(digest, common_name, country, state, locality,
                                              organisation, organisational_unit, email, domain_component,
                                              key_usage_list,
                                              extended_key_usage_list, subject_type, path_length, ip, dns)

        request_dict.update({'password': password, 'signerCert': signer_certificate, 'inKey': private_key,
                             'algorithm': algorithm, 'days': str(days)})

        payload = json.dumps(request_dict)

        response = self.http.http_post_json(self.webssl_req_generate_key_and_signed_cert_url, payload)

        json_data = json.loads(response.text)
        pkcs12_b64 = json_data['pkcs12']

        pkcs12 = base64.b64decode(str.encode(pkcs12_b64))

        return pkcs12

    def x509_sign_csr(self, digest, private_key, signer_certificate, csr, days):

        payload = json.dumps({'digest': digest, 'inKey': private_key, 'signerCert': signer_certificate, 'csr': csr,
                              'days': str(days)})

        response = self.http.http_post_json(self.webssl_x509_sign_csr_url, payload)

        json_data = json.loads(response.text)
        certificate = json_data['certificate']

        return certificate

    def x509_decode_crt(self, certificate):

        payload = json.dumps({'certificate': certificate})

        response = self.http.http_post_json(self.webssl_x509_decode_crt_url, payload)

        certificate = CRTDecoder.from_json(response.text)

        return certificate

    def pkcs12_export(self, password, certificate, private_key, signer_certificate):

        payload = json.dumps({'password': password, 'inKey': private_key, 'certificate': certificate,
                              'signerCert': signer_certificate})

        response = self.http.http_post_json(self.webssl_pkcs12_export_url, payload)

        json_data = json.loads(response.text)
        pkcs12_b64 = json_data['pkcs12']

        pkcs12 = base64.b64decode(str.encode(pkcs12_b64))

        return pkcs12

    @staticmethod
    def _prepare_cert_req(digest, common_name, country, state, locality,
                          organisation, organisational_unit, email, domain_component, key_usage_list,
                          extended_key_usage_list, subject_type, path_length, ip, dns):

        key_usage, extended_key_usage, subject_alt_name = [""] * 3
        subject_alt_name = {}
        basic_constraints = {}

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
        if domain_component is not None:
            dn['domainComponent'] = domain_component

        if 'endEntity' == subject_type:
            subject_type = 'End Entity'

        if key_usage_list is not None:
            key_usage = {'keyUsage': key_usage_list}

        if extended_key_usage_list is not None:
            extended_key_usage = {'enhancedKeyUsage': extended_key_usage_list}

        if ip is not None or dns is not None:
            subject_alt_name['subjectAltName'] = {}
        if ip is not None:
            subject_alt_name['subjectAltName']['IP'] = ip
        if dns is not None:
            subject_alt_name['subjectAltName']['DNS'] = dns

        if subject_type is not None or path_length is not None:
            basic_constraints['basicConstraints'] = {}
        if subject_type is not None:
            basic_constraints['basicConstraints']['subjectType'] = subject_type
        if path_length is not None:
            basic_constraints['basicConstraints']['pathLengthConstraint'] = path_length

        request_dict = {'digest': digest, 'subject': dn}
        request_dict.update(key_usage)
        request_dict.update(extended_key_usage)
        request_dict.update(subject_alt_name)
        request_dict.update(basic_constraints)

        return request_dict
