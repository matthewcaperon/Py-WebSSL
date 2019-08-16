import os
from file import File
from argparse import ArgumentParser
from webssl_api import WebSSLApi


def main():
    print("\n---- WebSSL Client----\n")

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
        operation.add_argument("-x509SignCsr", help="Sign a CSR to produce an x509 certificate", action='store_true')
        parser.add_argument("-cn", help="Common Name")
        parser.add_argument("-c", help="Country")
        parser.add_argument("-s", help="State")
        parser.add_argument("-l", help="Locality")
        parser.add_argument("-o", help="Organisation")
        parser.add_argument("-ou", help="Organisational Unit")
        parser.add_argument("-e", help="Email")
        parser.add_argument("-algorithm", help="Algorithm (rsa-2048, ecc-p256, rsa-4096, ecc-p521)")
        parser.add_argument("-days", help="Certificate validity in days")
        parser.add_argument("-subjectType", help="Certificate subject type (CA/End Entity)")
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
        webssl_api = WebSSLApi(args['debug'])

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

            # Read algorithm argument
            algorithm = args['algorithm']

            # WebSSL Generate Key
            pub_key_pem, prv_key_pem = webssl_api.generate_key(algorithm)

            # Save Private Key to file
            path = cwd + "\\" + args['outPrvKey']
            File.write(path, prv_key_pem)

            # Save Public Key to file
            path = cwd + "\\" + args['outPubKey']
            File.write(path, pub_key_pem)

        elif args['eciesEncrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read public key from file
            pub_key_pem = File.read(cwd + "\\" + args['inKey'])

            # Read data to encrypt from file
            data_to_encrypt = File.read(cwd + "\\" + args['in'])

            # WebSSL ECIES encrypt
            ecies = webssl_api.ecies_encrypt(pub_key_pem, str.encode(data_to_encrypt))

            # Save ECIES message to file
            path = cwd + "\\" + args['out']
            File.write(path, ecies)

        elif args['eciesDecrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read private key from file
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])

            # Read ECIES message from file
            ecies_pem = File.read(cwd + "\\" + args['in'])

            # WebSSL ECIES decrypt
            decrypted_data = webssl_api.ecies_decrypt(prv_key_pem, ecies_pem)

            # Save decrypted data to file
            File.write(cwd + "\\" + args['out'], decrypted_data)

        elif args['cmsEncrypt'] and args['recip'] and args['in'] and args['out']:

            # Read public key from file
            recip_cert = File.read(cwd + "\\" + args['recip'])

            # Read data to encrypt from file
            data_to_encrypt = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Encrypt
            cms = webssl_api.cms_encrypt(recip_cert, str.encode(data_to_encrypt))

            # Save CMS data to file
            File.write(cwd + "\\" + args['out'], cms)

        elif args['cmsDecrypt'] and args['inKey'] and args['in'] and args['out']:

            # Read private key from file
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])

            # Read data to encrypt from file
            ecies = File.read(cwd + "\\" + args['in'])

            # WebSSl CMS Decrypt
            data = webssl_api.cms_decrypt(prv_key_pem, str.encode(ecies))

            # Save decrypted data to file
            File.write(cwd + "\\" + args['out'], data)

        elif args['cmsSign'] and args['signer'] and args['inKey'] and args['in'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            data = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Sign
            cms = webssl_api.cms_sign(signer_cert_pem, prv_key_pem, str.encode(data))

            # Save CMS data to file
            File.write(cwd + "\\" + args['out'], cms)

        elif args['cmsVerify'] and args['in']:

            # Read CMS data from file
            cms = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Verified
            is_verified = webssl_api.cms_verify(cms)
            print("Verified: " + str(is_verified))

        elif args['cmsEncryptAndSign'] and args['recip'] and args['signer'] and args['inKey']\
                and args['in'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            recip_cert_pem = File.read(cwd + "\\" + args['recip'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            data = File.read(cwd + "\\" + args['in'])

            # WebSSL Encrypt and Sign
            cms = webssl_api.cms_encrypt_and_sign(signer_cert_pem, recip_cert_pem, prv_key_pem, str.encode(data))

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

        elif args['cmsSignAndEncrypt'] and args['recip'] and args['signer'] and args['inKey']\
                and args['in'] and args['out']:

            # Read input from files
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            recip_cert_pem = File.read(cwd + "\\" + args['recip'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            data = File.read(cwd + "\\" + args['in'])

            # WebSSL CMS Sign and Encrypt
            cms = webssl_api.cms_sign_and_encrypt(signer_cert_pem, recip_cert_pem, prv_key_pem, str.encode(data))

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

        elif args['reqGenerateCsr'] and args['inKey'] and args['cn'] and args['out']:

            # Read arguments
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            common_name = args["cn"]
            country = args["c"]
            locality = args["l"]
            state = args["s"]
            organisation = args["o"]
            organisational_unit = args["ou"]
            email = args["e"]

            # WebSSL Generate CSR
            csr = webssl_api.req_generate_csr(prv_key_pem, common_name, country, state, locality, organisation,
                                              organisational_unit, email)

            # Save CSR to file
            File.write(cwd + "\\" + args['out'], csr)

        elif args['reqGenKeyAndCert'] and args['algorithm'] and args['cn'] and args['subjectType'] \
                and args['days'] and args['outPrvKey'] and args['outPubKey']:

            # Read arguments
            algorithm = args['algorithm']
            common_name = args["cn"]
            country = args["c"]
            locality = args["l"]
            state = args["s"]
            organisation = args["o"]
            organisational_unit = args["ou"]
            email = args["e"]
            days = args["days"]
            subject_type = args["subjectType"]

            # WebSSL Generate Key and Certificate
            private_key, certificate = webssl_api.req_generate_key_and_cert(algorithm, common_name, country, state,
                                                                            locality, organisation, organisational_unit,
                                                                            email, days, subject_type)

            # Save Private Key to file
            path = cwd + "\\" + args['outPrvKey']
            File.write(path, private_key)

            # Save Certificate to file
            path = cwd + "\\" + args['outPubKey']
            File.write(path, certificate)

        elif args['x509SignCsr'] and args['signer'] and args['inKey'] and args['in'] \
                and args['days'] and args['outPubKey']:

            # Read arguments
            signer_cert_pem = File.read(cwd + "\\" + args['signer'])
            prv_key_pem = File.read(cwd + "\\" + args['inKey'])
            csr = File.read(cwd + "\\" + args['in'])
            days = args["days"]

            # WebSSL Sign CSR
            certificate = webssl_api.x509_sign_csr(prv_key_pem, signer_cert_pem, csr, days)

            # Save certificate to file
            File.write(cwd + "\\" + args['outPubKey'], certificate)

        else:
            parser.print_help()

    except Exception as e:
        print("Error: " + str(e))


if __name__ == "__main__":
    main()
