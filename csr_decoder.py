import json
from structures import *


class CSRDecoder:

    @staticmethod
    def from_json(json_object):

        common_name, country, locality, state, organisation, organisational_unit, email, domain_component,\
        subject_key_id, modulus, exponent, point, subject_type, path_len, algorithm, sig_algorithm, digest,\
        dns, ip, sig_value = [""] * 20
        key_usage = tuple()
        enhanced_key_usage = tuple()

        csr = json.loads(json_object)

        version = csr['version']
        common_name = csr['subject']['commonName']
        if 'country' in csr['subject']:
            country = csr['subject']['country']
        if 'locality' in csr['subject']:
            locality = csr['subject']['locality']
        if 'state' in csr['subject']:
            state = csr['subject']['state']
        if 'organisation' in csr['subject']:
            organisation = csr['subject']['organisation']
        if 'organisationalUnit' in csr['subject']:
            organisational_unit = csr['subject']['organisationalUnit']
        if 'email' in csr['subject']:
            email = csr['subject']['email']
        if 'domainComponent' in csr['subject']:
            domain_component = csr['subject']['domainComponent']

        if 'algorithm' in csr['publicKeyInfo']:
            algorithm = csr['publicKeyInfo']['algorithm']
        if 'modulus' in csr['publicKeyInfo']:
            modulus = csr['publicKeyInfo']['modulus']
        if 'exponent' in csr['publicKeyInfo']:
            exponent = csr['publicKeyInfo']['exponent']
        if 'point' in csr['publicKeyInfo']:
            point = csr['publicKeyInfo']['point']

        if 'keyUsage' in csr:
            key_usage = csr['keyUsage']

        if 'enhancedKeyUsage' in csr:
            enhanced_key_usage = csr['enhancedKeyUsage']

        if 'basicConstraints' in csr:
            if 'subjectType' in csr['basicConstraints']:
                subject_type = csr['basicConstraints']['subjectType']
            if 'pathLengthConstraint' in csr['basicConstraints']:
                path_len = csr['basicConstraints']['pathLengthConstraint']

        if 'subjectKeyId' in csr:
            subject_key_id = csr['subjectKeyId']

        if 'subjectAltName' in csr:
            if 'DNS' in csr['subjectAltName']:
                dns = csr['subjectAltName']['DNS']
            if 'IP' in csr['subjectAltName']:
                ip = csr['subjectAltName']['IP']

        if 'signature' in csr:
            if 'algorithm' in csr['signature']:
                sig_algorithm = csr['signature']['algorithm']
            if 'digest' in csr['signature']:
                digest = csr['signature']['digest']
            if 'value' in csr['signature']:
                sig_value = csr['signature']['value']

        subject = DN(common_name, country, locality, state, organisation, organisational_unit, email, domain_component)
        public_key_info = PublicKeyInfo(algorithm, modulus, exponent, point)
        basic_constraints = BasicConstraints(subject_type, path_len)
        subject_alt_name = SubjectAltName(dns, ip)
        signature = Signature(sig_algorithm, digest, sig_value)

        return CSR(version, subject, public_key_info, key_usage, enhanced_key_usage, basic_constraints, subject_key_id,
                   subject_alt_name, signature)

    @staticmethod
    def print_csr(csr):

        public_key_info, key_usage, enhanced_key_usage, subject_key_id, signature, subject_alt_name,\
        basic_constraints = [""] * 7

        version = '\tVersion: \n\t\t' + csr.version + '\n'
        subject = '\tSubject: '
        subject += '\n\t\tCN: ' + csr.subject.cn
        if len(csr.subject.c) > 0:
            subject += '\n\t\tC: ' + csr.subject.c
        if len(csr.subject.l) > 0:
            subject += '\n\t\tL: ' + csr.subject.l
        if len(csr.subject.s) > 0:
            subject += '\n\t\tS: ' + csr.subject.s
        if len(csr.subject.o) > 0:
            subject += '\n\t\tO: ' + csr.subject.o
        if len(csr.subject.ou) > 0:
            subject += '\n\t\tOU: ' + csr.subject.ou
        if len(csr.subject.e) > 0:
            subject += '\n\t\tE: ' + csr.subject.e
        if len(csr.subject.dc) > 0:
            subject += '\n\t\tDC: ' + csr.subject.dc
        subject += "\n"

        if len(csr.key_usage) > 0:
            key_usage = '\tKey Usage: \n\t\t' + ', '.join(csr.key_usage) + '\n'

        if len(csr.enhanced_key_usage) > 0:
            enhanced_key_usage = '\tEnhanced Key Usage: \n\t\t' + ', '.join(csr.enhanced_key_usage) + '\n'

        if len(csr.subject_key_id) > 0:
            subject_key_id = '\tSubject Key Id: \n\t\t' + csr.subject_key_id + '\n'

        if len(csr.basic_constraints.subject_type) > 0 and len(csr.basic_constraints.path_len) > 0:
            basic_constraints = '\tBasic Constraints:'
            basic_constraints += "\n\t\tSubject Type: " + csr.basic_constraints.subject_type
            basic_constraints += "\n\t\tPath Length: " + csr.basic_constraints.path_len
            basic_constraints += "\n"

        if len(csr.public_key_info.algorithm) > 0 and len(csr.public_key_info.modulus) > 0 and \
                len(csr.public_key_info.exponent) > 0:
            public_key_info = '\tPublic Key Info:'
            public_key_info += "\n\t\talgorithm: " + csr.public_key_info.algorithm
            if len(csr.public_key_info.modulus) > 0 and len(csr.public_key_info.exponent) > 0:
                public_key_info += "\n\t\tmodulus: " + csr.public_key_info.modulus
                public_key_info += "\n\t\texponent: " + csr.public_key_info.exponent
            else:
                public_key_info += "\n\t\tpoint: " + csr.public_key_info.point
            public_key_info += "\n"

        if len(csr.subject_alt_name.dns) > 0 or len(csr.subject_alt_name.ip) > 0:
            subject_alt_name = '\tSubject Alternative Name:'
            if len(csr.subject_alt_name.dns) > 0:
                subject_alt_name += "\n\t\tDNS: " + csr.subject_alt_name.dns
            if len(csr.subject_alt_name.ip) > 0:
                subject_alt_name += "\n\t\tIP: " + csr.subject_alt_name.ip
            subject_alt_name += "\n"

        if len(csr.signature.algorithm) > 0 and len(csr.signature.digest) > 0 and len(csr.signature.value) > 0:
            signature = '\tSignature:'
            signature += "\n\t\tAlgorithm: " + csr.signature.algorithm
            signature += "\n\t\tDigest: " + csr.signature.digest
            signature += "\n\t\tValue: " + csr.signature.value
            signature += "\n"

        print('Certificate Request:\n' + version + subject + public_key_info + key_usage + enhanced_key_usage + subject_key_id +
              basic_constraints + subject_alt_name + signature)
