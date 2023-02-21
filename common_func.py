import asn1tools
import rsa
import base64

RFC5280_ASN_PATH = 'rfc5280.asn'
RFC3279_ASN_PATH = 'rfc3279.asn'

foo_5280 = asn1tools.compile_files(RFC5280_ASN_PATH)
foo_3279 = asn1tools.compile_files(RFC3279_ASN_PATH)

BEGIN_TEXT = '-----BEGIN CERTIFICATE-----'
END_TEXT =   '-----END CERTIFICATE-----'

def ASN1_RSAPublicKey(public_key):
    encoded = foo_3279.encode('RSAPublicKey', {'modulus': public_key.n, 'publicExponent': public_key.e})
    return (encoded, len(encoded)*8)

def ASN1_DecodeRSAPublicKey(data):
    decoded = foo_3279.decode('RSAPublicKey', data)
    return rsa.PublicKey(decoded['modulus'], decoded['publicExponent'])

def PrintCertificate(cer_data):
    print(BEGIN_TEXT)
    for i in range(len(cer_data)//64 + 1):
        print(cer_data[64*i:64*(i+1)].decode())
        print('...')
        break
    print(END_TEXT)

class Certificate_PEM_file:
    def __init__(self, cer_file, CApub):
        self.CApub = CApub

        try:
            r = open(cer_file, 'r')
        except:
            raise TypeError("Không thể mở được file Certificate")

        certificate = ''
        for row in r:
            certificate += row[:-1]

        certificate = base64.b64decode(certificate[27:-24])
        rfc5280_der = asn1tools.compile_files(RFC5280_ASN_PATH, codec='der')

        decoded = rfc5280_der.decode('Certificate', certificate)
        
        self.signature = decoded['signature'][0]
        self.tbsCertificate = rfc5280_der.encode('TBSCertificate', decoded['tbsCertificate'])
        self.publickey = ASN1_DecodeRSAPublicKey(decoded['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'][0])
        # self.publickey_modulus = self.publickey.n
        # self.publickey_publicExponent = self.publickey.e
        self.valid = False

        # Xác thực chữ ký số
        try:
            ver = rsa.verify(self.tbsCertificate, self.signature, self.CApub)
            if ver == 'SHA-1': self.valid = True
        except:
            print("Chữ ký số không hợp lệ")

class Certificate_PEM:
    def __init__(self, cer, CApub):
        try:
            certificate = base64.b64decode(cer)
        except:
            print("Input không hợp lệ: Không phải dạng base64")
            return

        rfc5280_der = asn1tools.compile_files(RFC5280_ASN_PATH, codec='der')

        decoded = rfc5280_der.decode('Certificate', certificate)
        
        self.signature = decoded['signature'][0]
        self.tbsCertificate = rfc5280_der.encode('TBSCertificate', decoded['tbsCertificate'])
        self.publickey = ASN1_DecodeRSAPublicKey(decoded['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'][0])
        # self.publickey_modulus = self.publickey.n
        # self.publickey_publicExponent = self.publickey.e
        self.valid = False

        try:
            ver = rsa.verify(self.tbsCertificate, self.signature, CApub)
            if ver == 'SHA-1': self.valid = True
        except:
            return

def ReadHandshakeMessageData(mess):
    i = 0
    mess_type = []
    handshake_mess = []
    while i <= len(mess):
        payload_len = int(mess[i+1])*256+int(mess[i+2])
        if payload_len == 0:
            handshake_mess.append(None)
        else:
            handshake_mess.append(mess[3+i:3+payload_len+i])
        mess_type.append(mess[i])

        i += 3 + payload_len
        if i >= len(mess): break

    return mess_type, handshake_mess

def BlockCipherEncodeASN1(key, pubKey):
    foo = asn1tools.compile_files('block_cipher.asn')
    encoded = foo.encode('BlockCipher', {'algorithm':'AES128', 'key':(key, 128)})
    return rsa.encrypt(encoded, pubKey)

def BlockCipherDecodeASN1(data, privKey):
    foo = asn1tools.compile_files('block_cipher.asn')
    data = rsa.decrypt(data, privKey)
    decoded = foo.decode('BlockCipher', data)
    return decoded
