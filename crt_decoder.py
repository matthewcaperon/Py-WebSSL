import json
from structures import *


class CRTDecoder:

    @staticmethod
    def from_json(certificate_json):

        valid_from, valid_to, version, serial_number, common_name, country, locality, state, organisation, \
        organisational_unit, email, domain_component, authority_key_id, subject_key_id, modulus, \
        exponent, point, subject_type, path_len, algorithm, sig_algorithm, digest, sig_value = [""] * 23
        key_usage = tuple()
        enhanced_key_usage = tuple()

        certificate = json.loads(certificate_json)

        version = certificate['version']
        serial_number = certificate['serialNumber']
        valid_from = certificate['validFrom']
        valid_to = certificate['validTo']

        common_name = certificate['subject']['commonName']
        if 'country' in certificate['subject']:
            country = certificate['subject']['country']
        if 'locality' in certificate['subject']:
            locality = certificate['subject']['locality']
        if 'state' in certificate['subject']:
            state = certificate['subject']['state']
        if 'organisation' in certificate['subject']:
            organisation = certificate['subject']['organisation']
        if 'organisationalUnit' in certificate['subject']:
            organisational_unit = certificate['subject']['organisationalUnit']
        if 'email' in certificate['subject']:
            email = certificate['subject']['email']
        if 'domainComponent' in certificate['subject']:
            domain_component = certificate['subject']['domainComponent']

        if 'algorithm' in certificate['publicKeyInfo']:
            algorithm = certificate['publicKeyInfo']['algorithm']
        if 'modulus' in certificate['publicKeyInfo']:
            modulus = certificate['publicKeyInfo']['modulus']
        if 'exponent' in certificate['publicKeyInfo']:
            exponent = certificate['publicKeyInfo']['exponent']
        if 'point' in certificate['publicKeyInfo']:
            point = certificate['publicKeyInfo']['point']

        if 'keyUsage' in certificate:
            key_usage = certificate['keyUsage']

        if 'enhancedKeyUsage' in certificate:
            enhanced_key_usage = certificate['enhancedKeyUsage']

        if 'basicConstraints' in certificate:
            if 'subjectType' in certificate['basicConstraints']:
                subject_type = certificate['basicConstraints']['subjectType']
            if 'pathLengthConstraint' in certificate['basicConstraints']:
                path_len = certificate['basicConstraints']['pathLengthConstraint']

        if 'authorityKeyId' in certificate:
            authority_key_id = certificate['authorityKeyId']

        if 'subjectKeyId' in certificate:
            subject_key_id = certificate['subjectKeyId']

        if 'signature' in certificate:
            if 'algorithm' in certificate['signature']:
                sig_algorithm = certificate['signature']['algorithm']
            if 'digest' in certificate['signature']:
                digest = certificate['signature']['digest']
            if 'value' in certificate['signature']:
                sig_value = certificate['signature']['value']

        issuer = DN(common_name, country, locality, state, organisation, organisational_unit, email, domain_component)
        subject = DN(common_name, country, locality, state, organisation, organisational_unit, email, domain_component)
        public_key_info = PublicKeyInfo(algorithm, modulus, exponent, point)
        basic_constraints = BasicConstraints(subject_type, path_len)
        signature = Signature(sig_algorithm, digest, sig_value)

        return Certificate(version, serial_number, issuer, subject, valid_from, valid_to, public_key_info,
                           basic_constraints, key_usage, enhanced_key_usage, authority_key_id, subject_key_id,
                           signature)

    @staticmethod
    def print_certificate(certificate):

        public_key_info, key_usage, enhanced_key_usage, authority_key_id, subject_key_id, \
        signature, basic_constraints = [""] * 7

        version = '\tVersion: ' + certificate.version + '\n'

        issuer = '\tIssuer: '
        issuer += '\n\t\tCN: ' + certificate.issuer.cn
        if len(certificate.issuer.c) > 0:
            issuer += '\n\t\tC: ' + certificate.issuer.c
        if len(certificate.issuer.l) > 0:
            issuer += '\n\t\tL: ' + certificate.issuer.l
        if len(certificate.issuer.s) > 0:
            issuer += '\n\t\tS: ' + certificate.issuer.s
        if len(certificate.issuer.o) > 0:
            issuer += '\n\t\tO: ' + certificate.issuer.o
        if len(certificate.issuer.ou) > 0:
            issuer += '\n\t\tOU: ' + certificate.issuer.ou
        if len(certificate.issuer.e) > 0:
            issuer += '\n\t\tE: ' + certificate.issuer.e
        if len(certificate.issuer.dc) > 0:
            issuer += '\n\t\tDC: ' + certificate.issuer.dc
        issuer += "\n"

        subject = '\tSubject: '
        subject += '\n\t\tCN: ' + certificate.subject.cn
        if len(certificate.subject.c) > 0:
            subject += '\n\t\tC: ' + certificate.subject.c
        if len(certificate.subject.l) > 0:
            subject += '\n\t\tL: ' + certificate.subject.l
        if len(certificate.subject.s) > 0:
            subject += '\n\t\tS: ' + certificate.subject.s
        if len(certificate.subject.o) > 0:
            subject += '\n\t\tO: ' + certificate.subject.o
        if len(certificate.subject.ou) > 0:
            subject += '\n\t\tOU: ' + certificate.subject.ou
        if len(certificate.subject.e) > 0:
            subject += '\n\t\tE: ' + certificate.subject.e
        if len(certificate.subject.dc) > 0:
            subject += '\n\t\tDC: ' + certificate.subject.dc
        subject += "\n"

        serial_number = '\tSerial Number: \n\t\t' + certificate.serial_number + '\n'
        valid_from = '\tValid From: \n\t\t' + certificate.valid_from + '\n'
        valid_to = '\tValid To: \n\t\t' + certificate.valid_to + '\n'

        if len(certificate.key_usage) > 0:
            key_usage = '\tKey Usage: \n\t\t' + ', '.join(certificate.key_usage) + '\n'

        if len(certificate.enhanced_key_usage) > 0:
            enhanced_key_usage = '\tEnhanced Key Usage: \n\t\t' + ', '.join(certificate.enhanced_key_usage) + '\n'

        if len(certificate.authority_key_id) > 0:
            authority_key_id = '\tAuthority Key Id: \n\t\t' + certificate.authority_key_id + '\n'

        if len(certificate.subject_key_id) > 0:
            subject_key_id = '\tSubject Key Id: \n\t\t' + certificate.subject_key_id + '\n'

        if len(certificate.basic_constraints.subject_type) > 0 and len(certificate.basic_constraints.path_len) > 0:
            basic_constraints = '\tBasic Constraints:'
            basic_constraints += "\n\t\tSubject Type: " + certificate.basic_constraints.subject_type
            basic_constraints += "\n\t\tPath Length: " + certificate.basic_constraints.path_len
            basic_constraints += "\n"

        if len(certificate.public_key_info.algorithm) > 0 and len(certificate.public_key_info.modulus) > 0 and \
                len(certificate.public_key_info.exponent) > 0:
            public_key_info = '\tPublic Key Info:'
            public_key_info += "\n\t\talgorithm: " + certificate.public_key_info.algorithm
            if len(certificate.public_key_info.modulus) > 0 and len(certificate.public_key_info.exponent) > 0:
                public_key_info += "\n\t\tmodulus: " + certificate.public_key_info.modulus
                public_key_info += "\n\t\texponent: " + certificate.public_key_info.exponent
            else:
                public_key_info += "\n\t\tpoint: " + certificate.public_key_info.point
            public_key_info += "\n"

        if len(certificate.signature.algorithm) > 0 and len(certificate.signature.digest) > 0 \
                and len(certificate.signature.value) > 0:
            signature = '\tSignature:'
            signature += "\n\t\tAlgorithm: " + certificate.signature.algorithm
            signature += "\n\t\tDigest: " + certificate.signature.digest
            signature += "\n\t\tValue: " + certificate.signature.value
            signature += "\n"

        print('Certificate:\n' + version + serial_number + issuer + subject + public_key_info + valid_from + valid_to +
              key_usage + enhanced_key_usage + authority_key_id + subject_key_id + basic_constraints + signature)
