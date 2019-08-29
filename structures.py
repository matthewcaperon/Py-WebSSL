from dataclasses import dataclass


@dataclass
class DN:
    cn: str
    c: str
    l: str
    s: str
    o: str
    ou: str
    e: str
    dc: str


@dataclass
class PublicKeyInfo:
    algorithm: str
    modulus: str
    exponent: str
    point: str


@dataclass
class Signature:
    algorithm: str
    digest: str
    value: str


@dataclass
class BasicConstraints:
    subject_type: str
    path_len: str


@dataclass
class CSR:
    subject: DN
    public_key_info: PublicKeyInfo
    key_usage: tuple
    enhanced_key_usage: tuple
    basic_constraints: BasicConstraints
    subject_key_id: str
    signature: Signature


@dataclass
class Certificate:
    version: str
    serial_number: str
    issuer: DN
    subject: DN
    valid_from: str
    valid_to: str
    public_key_info: PublicKeyInfo
    basic_constraints: BasicConstraints
    key_usage: tuple
    enhanced_key_usage: tuple
    authority_key_id: str
    subject_key_id: str
    signature: Signature
