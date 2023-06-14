#!/usr/bin/env python3
import abc
import sys

# asn1crypto library
import asn1crypto.core
from asn1crypto import x509

# Protobuf library
from google.protobuf.timestamp_pb2 import *

# Protobuf mutator library
from asn1_pdu_pb2 import *
from asn1_universal_types_pb2 import *
from x509_certificate_pb2 import *


class GenericEncoder(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def _encode(asn1):
        raise NotImplementedError()

    @classmethod
    def encode(cls, asn1):
        if isinstance(asn1, asn1crypto.core.Void):
            return None
        else:
            return cls._encode(asn1)


class PDUEncoder(GenericEncoder):
    """
    Class encoding arbitrary ASN.1 to a PDU

    Note: it is not able to handle all possibilities, so only use as last option
    (e.g. if no specific protobuf class exists) or for simple objects
    """
    ASN1_ClASS = {
        0: Class.Universal,
        1: Class.Application,
        2: Class.ContextSpecific,
        3: Class.Private,
    }

    ASN1_ENCODING = {
        0: Encoding.Primitive,
        1: Encoding.Constructed,
    }

    @staticmethod
    def _encode(asn1):
        try:
            asn1 = asn1.chosen
        except AttributeError:
            pass

        if isinstance(asn1, asn1crypto.core.Any):
            asn1.parse()
            asn1 = asn1._parsed[0]
        elif isinstance(asn1, asn1crypto.core.Void):
            return None

        identifier = Identifier(
            id_class=PDUEncoder.ASN1_ClASS[asn1.class_],
            encoding=PDUEncoder.ASN1_ENCODING[asn1.method],
            tag_num=TagNumber(low_tag_num=asn1.tag),
        )

        values = []
        if asn1.method == 0:
            values.append(ValueElement(val_bits=asn1.contents))
        else:
            # Constructed type, recursively build this
            for i in range(len(asn1)):
                val = PDUEncoder._encode(asn1[i])
                if val is not None:
                    values.append(ValueElement(pdu=val, val_bits=b""))
        return PDU(id=identifier, len=Length(), val=Value(val_array=values))


class BitStringEncoder(GenericEncoder):
    @staticmethod
    def _encode(string):
        return BitString(
            val=string,
            unused_bits=0,
        )


class SignatureValueEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return SignatureValue(
            value=BitStringEncoder.encode(asn1.native),
        )


class AlgorithmIdentifierSequenceEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return AlgorithmIdentifierSequence(
            object_identifier=PDUEncoder.encode(asn1["algorithm"]),
            parameters=PDUEncoder.encode(asn1["parameters"]),
        )


class SignatureAlgorithmEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return SignatureAlgorithm(
            value=AlgorithmIdentifierSequenceEncoder.encode(asn1),
        )


class VersionEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return Version(
            value=asn1.native,
        )


class SerialNumberEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        # For some reason, integer size is not properly encoded in ASN.1, so use
        # our own PDU
        return SerialNumber(
            value=Integer(val=asn1.contents),
            pdu=PDUEncoder.encode(asn1),
        )


class UTCTimeEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        t = Timestamp()
        t.FromDatetime(asn1.native)
        return UTCTime(
            time_stamp=t,
        )


class GeneralizedTimeEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        t = Timestamp()
        t.FromDatetime(asn1.native)
        return GeneralizedTime(
            time_stamp=t,
        )


class TimeChoiceEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        if isinstance(asn1.chosen, asn1crypto.core.UTCTime):
            return TimeChoice(
                utc_time=UTCTimeEncoder.encode(asn1.chosen),
                generalized_time=GeneralizedTime(time_stamp=Timestamp(seconds=0, nanos=0)),
            )
        else:
            return TimeChoice(
                generalized_time=GeneralizedTimeEncoder.encode(asn1.chosen),
            )


class NotBeforeEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return NotBefore(
            value=TimeChoiceEncoder.encode(asn1),
        )


class NotAfterEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return NotAfter(
            value=TimeChoiceEncoder.encode(asn1),
        )


class ValidityEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        # For some reason, validity is correctly represented in protobuf but not
        # included when converted to ASN.1, so use our own PDU
        return Validity(
            value=ValiditySequence(
                not_before=NotBeforeEncoder.encode(asn1["not_before"]),
                not_after=NotAfterEncoder.encode(asn1["not_after"]),
            ),
            pdu=PDUEncoder.encode(asn1),
        )


class NameEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return Name(
            value=PDUEncoder.encode(asn1),
        )


class SubjectPublicKeyEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return SubjectPublicKey(
            value=BitStringEncoder.encode(asn1.parsed.dump()),
        )


class SubjectPublicKeyInfoEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return SubjectPublicKeyInfo(
            value=SubjectPublicKeyInfoSequence(
                algorithm_identifier=AlgorithmIdentifierSequenceEncoder.encode(asn1["algorithm"]),
                subject_public_key=SubjectPublicKeyEncoder.encode(asn1["public_key"]),
            ),
        )


class UniqueIdentifierEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return UniqueIdentifier(
            value=BitStringEncoder.encode(asn1.native),
        )


class ObjectIdentifierEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        identifier = asn1.dotted
        objid = ObjectIdentifier(
            root=int(identifier.split(".")[0]),
            small_identifier=int(identifier.split(".")[1]),
        )
        for i in identifier.split(".")[2:]:
            objid.subidentifier.append(int(i))
        return objid


class AuthorityKeyIdentifierEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return AuthorityKeyIdentifier(
            key_identifier=OctetString(val=asn1["key_identifier"].native),
            authority_cert_issuer=PDUEncoder.encode(asn1["authority_cert_issuer"]),
            authority_cert_serial_number=PDUEncoder.encode(asn1["authority_cert_serial_number"]),
        )


class SubjectKeyIdentifierEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return SubjectKeyIdentifier(
            key_identifier=OctetString(val=asn1.native),
        )


class BasicConstraintsEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return BasicConstraints(
            ca=Boolean(val=asn1["ca"].native),
            path_len_constraint=asn1["path_len_constraint"].native,
        )


class RawExtensionEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return RawExtension(
            extn_id=ObjectIdentifierEncoder.encode(asn1["extn_id"]),
            extn_value = OctetString(val=asn1["extn_value"].parsed.dump()),
            #pdu=PDUEncoder.encode(asn1["extn_value"]),
        )


class ExtensionEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        kwargs = {
            #"extn_id": ObjectIdentifierEncoder.encode(asn1["extn_id"]),
            "critical": Boolean(val=asn1["critical"].native),
            "raw_extension": RawExtensionEncoder.encode(asn1),
        }

        extn_value = asn1["extn_value"].parsed
        if asn1["extn_id"].native == "authority_key_identifier":
            kwargs["authority_key_identifier"] = AuthorityKeyIdentifierEncoder.encode(extn_value)
        elif asn1["extn_id"].native == "key_identifier":
            kwargs["subject_key_identifier"] = SubjectKeyIdentifierEncoder.encode(extn_value)
        elif asn1["extn_id"].native == "basic_constraints":
            kwargs["basic_constraints"] = BasicConstraintsEncoder.encode(extn_value)

        return Extension(**kwargs)


class ExtensionsEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return Extensions(
            value=ExtensionSequence(
                extension=ExtensionEncoder.encode(asn1[0]),
                extensions=[ExtensionEncoder.encode(ext) for ext in list(asn1)[1:]],
            ),
            #pdu=PDUEncoder.encode(asn1),
        )


class TBSCertificateEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        # TODO: Encode extensions
        # Currently, encoding extensions results an invalid certificate
        # Note: In any case, extensions are apparently not mutated
        return TBSCertificate(
            value=TBSCertificateSequence(
                version=VersionEncoder.encode(asn1["version"]),
                serial_number=SerialNumberEncoder.encode(asn1["serial_number"]),
                signature_algorithm=SignatureAlgorithmEncoder.encode(asn1["signature"]),
                issuer=NameEncoder.encode(asn1["issuer"]),
                validity=ValidityEncoder.encode(asn1["validity"]),
                subject=NameEncoder.encode(asn1["subject"]),
                subject_public_key_info=SubjectPublicKeyInfoEncoder.encode(asn1["subject_public_key_info"]),
                issuer_unique_id=UniqueIdentifierEncoder.encode(asn1["issuer_unique_id"]),
                subject_unique_id=UniqueIdentifierEncoder.encode(asn1["subject_unique_id"]),
                #extensions=ExtensionsEncoder.encode(asn1["extensions"]),
            ),
        )


class CertificateEncoder(GenericEncoder):
    @staticmethod
    def _encode(asn1):
        return X509Certificate(
            tbs_certificate=TBSCertificateEncoder.encode(asn1["tbs_certificate"]),
            signature_algorithm=SignatureAlgorithmEncoder.encode(asn1["signature_algorithm"]),
            signature_value=SignatureValueEncoder.encode(asn1["signature_value"]),
        )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./asn1_pdu_pb2.py <in path> <out path>", file=sys.stderr)
        exit(1)

    with open(sys.argv[1], "rb") as f:
        der = f.read()

    cert = x509.Certificate.load(der)
    proto_cert = CertificateEncoder.encode(cert)
    print(proto_cert)
    out = proto_cert.SerializeToString()
    if sys.argv[2] == "-":
        sys.stdout.buffer.write(out)
    else:
        with open(sys.argv[2], "wb") as f:
            f.write(out)
