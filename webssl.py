import os
from argparse import ArgumentParser
from file import File
from api import Api
from csr_decoder import CSRDecoder
from crt_decoder import CRTDecoder


def main():
    print("\n---- WebSSL Command Line Tool----\n")

    try:
        parser = ArgumentParser()
        operation = parser.add_mutually_exclusive_group(required=True)
        operation.add_argument("-generateKey", help="Generate key command", action='store_true')
        operation.add_argument("-eciesEncrypt", help="ECIES encrypt command", action='store_true')
        operation.add_argument("-eciesDecrypt", help="ECIES decrypt command", action='store_true')
        operation.add_argument("-getStatus", help="Reads the status of the WebSSL HSM", action='store_true')
        operation.add_argument("-getInfo", help="Reads information about a WebSSL HSM", action='store_true')
        operation.add_argument("-cmsEncrypt", help="Cryptographic Message Syntax encrypt operation",
                               action='store_true')
        operation.add_argument("-cmsDecrypt", help="Cryptographic Message Syntax decrypt operation",
                               action='store_true')
        operation.add_argument("-cmsSign", help="Cryptographic Message Syntax sign operation", action='store_true')
        operation.add_argument("-cmsVerify", help="Cryptographic Message Syntax verify operation", action='store_true')
        operation.add_argument("-cmsEncryptAndSign", help="Cryptographic Message Syntax encrypt and sign Operation",
                               action='store_true')
        operation.add_argument("-cmsVerifyAndDecrypt", help="Cryptographic Message Syntax verify and decrypt operation",
                               action='store_true')
        operation.add_argument("-cmsSignAndEncrypt", help="Cryptographic Message Syntax sign and encrypt Operation",
                               action='store_true')
        operation.add_argument("-cmsDecryptAndVerify", help="Cryptographic Message Syntax decrypt and verify Operation",
                               action='store_true')
        operation.add_argument("-reqGenerateCsr", help="Generate a PKCS #10 certificate signing request",
                               action='store_true')
        operation.add_argument("-reqGenKeyAndCert", help="Generate a key pair and self signed certificate",
                               action='store_true')
        operation.add_argument("-reqGenKeyAndSignedCert", help="Generate a key pair and signed certificate",
                               action='store_true')
        operation.add_argument("-reqDecodeCrt", help="Decodes an x509 certificate", action='store_true')
        operation.add_argument("-reqDecodeCsr", help="Decodes a CSR", action='store_true')
        operation.add_argument("-x509SignCsr", help="Sign a CSR to produce an x509 certificate", action='store_true')
        operation.add_argument("-x509DecodeCrt", help="Decodes an x509 certificate", action='store_true')
        operation.add_argument("-pkcs12Export", help="Encrypt certificate and keys and export as a PKCS#12 file",
                               action='store_true')
        parser.add_argument("-cn", help="Common Name")
        parser.add_argument("-c", help="Country")
        parser.add_argument("-s", help="State")
        parser.add_argument("-l", help="Locality")
        parser.add_argument("-o", help="Organisation")
        parser.add_argument("-ou", help="Organisational Unit")
        parser.add_argument("-e", help="Email")
        parser.add_argument("-dc", help="Domain Component")
        parser.add_argument("-algorithm", help="Algorithm (aes-128, rsa-2048, ecc-p256, rsa-4096, ecc-p521)")
        parser.add_argument("-digest", help="Digest (sha-256)", default='sha-256')
        parser.add_argument("-password", help="PKCS12 password")
        parser.add_argument("-days", help="Certificate validity in days")
        parser.add_argument("-subjectType", help="Certificate subject type (CA/endEntity)")
        parser.add_argument("-pathLength", help="CA certificate path length constraint", default='0')
        parser.add_argument("-ip", help="Host IP address")
        parser.add_argument("-dns", help="Host DNS name")
        parser.add_argument("-keyUsageList", help='A list of key usage extensions ('
                                                  'CRLSign/dataEncipherment/decipherOnly/digitalSignature/encipherOnly/'
                                                  'keyAgreement/keyCertSign/keyEncipherment/nonRepudiation)', nargs='+')
        parser.add_argument("-extendedKeyUsageList", help='A list of extended key usage extensions'
                                                          ' (clientAuthentication/serverAuthentication/emailProtection/'
                                                          'codeSigning/timeStamping)', nargs='+')
        parser.add_argument("-inKey", help="Input key file")
        parser.add_argument("-signer", help="Input certificate file")
        parser.add_argument("-recip", help="Input certificate file")
        parser.add_argument("-in", help="Input data file")
        parser.add_argument("-out", help="Output data file")
        parser.add_argument("-outPrvKey", help="Output private key file")
        parser.add_argument("-outPubKey", help="Output public key/certificate file")
        parser.add_argument("-debug", help="Print HTTP request and response", action='store_true')

        # Parse arguments
        args = vars(parser.parse_args())

        # Get current working directory
        cwd = os.getcwd()

        # Initialise WebSSL API
        webssl_api = Api(args['debug'])

        if args['getStatus']:

            # WebSSL Get Status
            bat_voltage, temp, free_mem, used_mem = webssl_api.get_status()

            print("HSM battery voltage: " + bat_voltage)
            print("HSM temperature: " + temp)
            print("HSM free memory: " + free_mem)
            print("HSM used memory: " + used_mem)

        elif args['getInfo']:

            # WebSSL Get Info
            hsm_id, hsm_type = webssl_api.get_info()

            print("HSM id: " + hsm_id)
            print("HSM type: " + hsm_type)

        elif args['generateKey'] and args['algorithm'] and args['outPrvKey'] and args['outPubKey']:

            # WebSSL Generate Key
            pub_key_pem, prv_key_pem = webssl_api.generate_key(args['algorithm'])

            # Save Private Key to file
            path = cwd + "\\" + args['outPrvKey']
            File.write(path, prv_key_pem)

            # Save Public Key to file
            path = cwd + "\\" + args['outPubKey']
            File.write(path, pub_key_pem)

        elif args['eciesEncrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read input from files
            pub_key_pem = File.read(cwd + "\\" + args['inKey'])
            data_to_encrypt = File.read(cwd + "\\" + args['in'])

            # WebSSL ECIES encrypt
            ecies = webssl_api.ecies_encrypt(pub_key_pem, str.encode(data_to_encrypt))

            # Save ECIES message to file
            path = cwd + "\\" + args['out']
            File.write(path, ecies)

        elif args['eciesDecrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read input from files
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            ecies_pem = File.read(cwd + "\\" + args['in'])

            # WebSSL ECIES decrypt
            decrypted_data = webssl_api.ecies_decrypt(prv_key_pem, ecies_pem)

            # Save decrypted data to file
            File.write(cwd + "\\" + args['out'], decrypted_data)

        elif args['cmsEncrypt'] and args['algorithm'] and args['recip'] and args['in'] and args['out']:

            # Read input from files
            recip_cert = File.read(cwd + "\\" + args['recip'])
            data_to_encrypt = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Encrypt
            cms = webssl_api.cms_encrypt(args['algorithm'], recip_cert, str.encode(data_to_encrypt))

            # Save CMS data to file
            File.write(cwd + "\\" + args['out'], cms)

        elif args['cmsDecrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read input from files
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            ecies = File.read(cwd + "\\" + args['in'])

            # WebSSl CMS Decrypt
            data = webssl_api.cms_decrypt(prv_key_pem, str.encode(ecies))

            # Save decrypted data to file
            File.write(cwd + "\\" + args['out'], data)

        elif args['cmsSign'] and args["digest"] and args['signer'] and args['inKey'] and args['in'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            data = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Sign
            cms = webssl_api.cms_sign(args["digest"], signer_cert_pem, prv_key_pem, str.encode(data))

            # Save CMS data to file
            File.write(cwd + "\\" + args['out'], cms)

        elif args['cmsVerify'] and args['in']:

            # Read CMS data from file
            cms = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Verified
            is_verified = webssl_api.cms_verify(cms)
            print("Verified: " + str(is_verified))

        elif args['cmsEncryptAndSign'] and args['recip'] and args['signer'] and args['inKey'] \
                and args['in'] and args['algorithm'] and args['digest'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            recip_cert_pem = File.read(cwd + "\\" + args['recip'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            data = File.read(cwd + "\\" + args['in'])

            # WebSSL Encrypt and Sign
            cms = webssl_api.cms_encrypt_and_sign(args['algorithm'], args["digest"], signer_cert_pem, recip_cert_pem,
                                                  prv_key_pem, str.encode(data))

            # Save CMS data to file
            File.write(cwd + "\\" + args['out'], cms)

        elif args['cmsVerifyAndDecrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read input from files
            cms = File.read(cwd + "\\" + args['in'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])

            # WebSSL CMS Verify and Decrypt
            is_verified, data = webssl_api.cms_verify_and_decrypt(prv_key_pem, cms)

            # Save CMS to data to file
            print("Verified: " + str(is_verified))
            File.write(cwd + "\\" + args['out'], data)

        elif args['cmsSignAndEncrypt'] and args['recip'] and args['signer'] and args['inKey'] \
                and args['in'] and args['algorithm'] and args['digest'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            recip_cert_pem = File.read(cwd + "\\" + args['recip'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            data = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Sign and Encrypt
            cms = webssl_api.cms_sign_and_encrypt(args['algorithm'], args["digest"], signer_cert_pem, recip_cert_pem, prv_key_pem,
                                                  str.encode(data))

            # Save CMS data to file
            File.write(cwd + "\\" + args['out'], cms)

        elif args['cmsDecryptAndVerify'] and (args['inKey'] is not None) and (args['in'] is not None) \
                and (args['out'] is not None):

            # Read input from files
            cms = File.read(cwd + "\\" + args['in'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])

            # WebSSL Decrypt and Verify
            is_verified, data = webssl_api.cms_decrypt_and_verify(prv_key_pem, cms)

            # Save CMS data to file
            print("Verified: " + str(is_verified))
            File.write(cwd + "\\" + args['out'], data)

        elif args['reqGenerateCsr'] and args['inKey'] and args['cn'] and args["digest"] and args['out']:

            # Read arguments
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])

            # WebSSL Generate CSR
            csr = webssl_api.req_generate_csr(args["digest"], prv_key_pem, args["cn"], args["c"], args["s"], args["l"],
                                              args["o"],
                                              args["ou"], args["e"], args["dc"], args['keyUsageList'],
                                              args['extendedKeyUsageList'], "End Entity", args['pathLength'],
                                              args['ip'], args['dns'])

            # Save CSR to file
            File.write(cwd + "\\" + args['out'], csr)

        elif args['reqGenKeyAndCert'] and args['algorithm'] and args['digest'] and args['cn'] and args['days'] \
                and args['outPrvKey'] and args['outPubKey']:

            # WebSSL generate key and self signed certificate
            private_key, certificate = webssl_api.req_generate_key_and_self_signed_cert(args['algorithm'], args["digest"],
                                                                                        args["cn"], args["c"],
                                                                                        args["s"], args["l"],
                                                                                        args["o"],
                                                                                        args["ou"], args["e"],
                                                                                        args["dc"], args["days"],
                                                                                        args['keyUsageList'],
                                                                                        args['extendedKeyUsageList'],
                                                                                        args["subjectType"],
                                                                                        args['pathLength'],
                                                                                        args['ip'], args['dns'])
            # Save Private Key to file
            path = cwd + "\\" + args['outPrvKey']
            File.write(path, private_key)

            # Save Certificate to file
            path = cwd + "\\" + args['outPubKey']
            File.write(path, certificate)

        elif args['reqGenKeyAndSignedCert'] and args['password'] and args['digest'] and args['algorithm'] \
                and args['cn'] and args['inKey'] and args['signer'] and args['days'] and args['out']:

            # Read input from files
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])

            # WebSSL generate key and certificate
            pkcs12 = webssl_api.req_generate_key_and_signed_cert(args["password"], args['algorithm'], args["digest"],
                                                                 signer_cert_pem, prv_key_pem, args["cn"], args["c"],
                                                                 args["s"], args["l"], args["o"], args["ou"], args["e"],
                                                                 args["dc"], args["days"], args['keyUsageList'],
                                                                 args['extendedKeyUsageList'],
                                                                 args["subjectType"], args['pathLength'],
                                                                 args['ip'], args['dns'])

            # Save pkcs12 to file
            File.write_bytes(cwd + "\\" + args['out'], pkcs12)

        elif args['reqDecodeCsr']:

            # Read input from file
            csr_pem = File.read(cwd + "\\" + args['in'])

            # WebSSL decode certificate signing request
            csr = webssl_api.req_decode_csr(csr_pem)
            CSRDecoder.print_csr(csr)

        elif args['x509SignCsr'] and args['digest'] and args['signer'] and args['inKey'] and args['in'] \
                and args['days'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            csr = File.read(cwd + "\\" + args['in'])

            # WebSSL sign CSR
            certificate = webssl_api.x509_sign_csr(args['digest'], prv_key_pem, signer_cert_pem, csr, args["days"])

            # Save certificate to file
            File.write(cwd + "\\" + args['out'], certificate)

        elif args['x509DecodeCrt'] and args['in']:

            # Read input from file
            cert_pem = File.read(cwd + "\\" + args['in'])

            # WebSSL decode x509 certificate
            certificate = webssl_api.x509_decode_crt(cert_pem)
            CRTDecoder.print_certificate(certificate)

        elif args['pkcs12Export'] and args["password"] and args['signer'] and args['inKey'] and args['in'] and args[
            "out"]:

            # Read input from files
            cert_pem = File.read(cwd + "\\" + args['in'])
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])

            # WebSSL export to PKCS#12 file
            pkcs12 = webssl_api.pkcs12_export(args["password"], cert_pem, prv_key_pem, signer_cert_pem)

            # Save pkcs12 to file
            File.write_bytes(cwd + "\\" + args['out'], pkcs12)

        else:
            parser.print_help()

    except Exception as e:
        print("Error: " + str(e))


if __name__ == "__main__":
    main()
