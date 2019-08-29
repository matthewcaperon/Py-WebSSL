# A Python command line tool for utilising WebSSL.io
WebSSL.io is a HTTP accessible Hardware Security Module (HSM) with a variety of cryptographic functions. This command line tool handles the composition and transfer of HTTP-JSON requests and responses to a remote HSM.
The remote HSM provides the WebSSL HTTP API.

Go to [WebSSL.io](https://www.webssl.io) for the complete API documentation.

## Prerequisites

This command line tool requires the Python [Requests](https://2.python-requests.org//en/v0.10.7/) library


## Help
To view the full list of command line arguments, use the following command:

```bash
python webssl.py -h
```

## Examples
The following are command line examples using the WebSSL HTTP API:

### Get HSM Info

```bash
python webssl.py -getInfo
```

### Get HSM Status

```bash
python webssl.py -getStatus
```

### Generate Key

```bash
python webssl.py -generateKey -algorithm ecc-p256 -outPrvKey private.key -outPubKey public.key
```

### CMS Encrypt

```bash
python webssl.py -cmsEncrypt -algorithm aes-128 -recip recipient.crt -in data.txt -out encrypted_data.cms
```

### CMS Decrypt

```bash
python webssl.py -cmsDecrypt -inKey recipient.key -in encrypted_data.cms -out data.txt
```

### CMS Sign

```bash
python webssl.py -cmsSign -digest sha-256 -signer signer.crt -inKey signer.key -in data.txt -out signed_data.cms
```

### CMS Verify

```bash
python webssl.py -cmsVerify -in signed_data.cms
```

### CMS Encrypt and Sign

```bash
python webssl.py -cmsEncryptAndSign -algorithm aes-128 -digest sha-256 -signer signer.crt -inKey signer.key -recip recipient.crt -in data.txt -out encrypted_and_signed.cms
```

### CMS Verify and Decrypt

```bash
python webssl.py -cmsVerifyAndDecrypt -inKey recipient.key -in encrypted_and_signed.cms -out data.txt
```

### CMS Sign and Encrypt

```bash
python webssl.py -cmsSignAndEncrypt -algorithm aes-128 -digest sha-256 -signer signer.crt -inKey signer.key -recip recipient.crt -in data.txt -out signed_and_encrypted.cms
```

### CMS Decrypt and Verify

```bash
python webssl.py -cmsDecryptAndVerify -inKey recipient.key -in signed_and_encrypted.cms -out data.txt
```

### Generate CSR

```bash
python webssl.py -reqGenerateCsr -cn test.example.com -digest sha-256 -inKey server.key -out server.csr -subjectType endEntity -keyUsageList digitalSignature keyEncipherment -extendedKeyUsageList clientAuthentication serverAuthentication
```

### Decode CSR

```bash
python webssl.py -reqDecodeCsr -in server.csr
```

### Generate Key and Self Signed Certificate

```bash
python webssl.py -reqGenKeyAndCert -algorithm rsa-2048 -digest sha-256 -cn testCA -days 365 -subjectType CA -pathLength 1 -outPrvKey ca.key -outPubKey ca.crt -keyUsageList digitalSignature nonRepudiation keyCertSign CRLSign -extendedKeyUsageList  clientAuthentication serverAuthentication
```

### Sign CSR

```bash
python webssl.py -x509SignCsr -signer ca.crt -inKey ca.key -in server.csr -days 365 -out server.crt
```

### Generate Key and Signed Certificate

```bash
python webssl.py -reqGenKeyAndSignedCert -password 1234 -algorithm rsa-2048 -digest sha-256 -signer ca.crt -inKey ca.key -cn user1 -e user1@email.com -days 365 -subjectType endEntity -keyUsageList digitalSignature nonRepudiation keyEncipherment -extendedKeyUsageList  emailProtection -out user1.p12
```

### Decode Certificate

```bash
python webssl.py -x509DecodeCrt -in server.crt
```

### ECIES Encrypt

```bash
python webssl.py -eciesEncrypt -inKey public.key -in data.txt -out encrypted_data.ecies
```

### ECIES Decrypt

```bash
python webssl.py -eciesDecrypt -inKey private.key -in encrypted_data.ecies -out data.txt
```

### Export PKCS12

```bash
python webssl.py -pkcs12Export -password 1234 -signer signer.crt -inKey signer.key -in user1.crt -out user1.p12
```
