import socket
import rsa
import base64
from common_func import *
from asn1tools.codecs import restricted_utc_time_to_datetime as ut2dt
from asn1 import ASN1
from _thread import *

############### CA key #################
# n, e
CApub  = rsa.PublicKey (29168623252785354452421324498503678015422860934849817475337334239651001217600025701418638724474809721158682729632678713367350325701797899817595268765817603327654164254517390206298518001824346346391367670978938422966272870497577718801862098155093820779848076938401205806480088038123682253549446041222767223681871209891946128254636808798151098615544414964770715346189578688461190409759116813541808230291779930361178504809848269543566367990765566457122439886866444699616707117850663902857968796931852736598651991750138190478951216862736262267274704391647618393262609912618490112016814640215008996979887749607944860028803, 65537)
# n, e, d, p, q
CApriv = rsa.PrivateKey(29168623252785354452421324498503678015422860934849817475337334239651001217600025701418638724474809721158682729632678713367350325701797899817595268765817603327654164254517390206298518001824346346391367670978938422966272870497577718801862098155093820779848076938401205806480088038123682253549446041222767223681871209891946128254636808798151098615544414964770715346189578688461190409759116813541808230291779930361178504809848269543566367990765566457122439886866444699616707117850663902857968796931852736598651991750138190478951216862736262267274704391647618393262609912618490112016814640215008996979887749607944860028803, 65537, 8649066262895429956725263575986419501559614516180730015078969380336876980356459701476546169838701455838330736606067495260199869987381762777596302209837702144838844835101338844912020695629225056829324625023020742077049310959907041968301663998168030566165489405129173328613265038754558756628516760355567962018904385833233668300115803661763395454080120802874808002482100308347393232102848735189577123099760102232118347255001758980140689802577545956036814874353193725197307612167866873493358174959117603920096768585302505695038228590425972864033969501724496915175645764319317726759437694579078527759040867082506374291545, 3256419269241904542626793983304388976868914433474676866077697691398086262263802328983935627871365027903306664461078373909816949595162457292908669449851374575105705394636413199662631274295294828813227978553701192670930606568054885878267840962740261836496491194986036099038252203729842255484582868617698707106524420994694908390247, 8957268963580300691495894377811399642886023030843509705155297287793187474864690296555806022535846816526046835489160784358898006845106003723131111468429780670881161490605081306850602350046546728212816175262455245259031431904810085617025003892243500095589555283356218255792119536616377206149)
############### CA key #################

############### certificate data field #################
# Version
_version = 'v1'
# Serial number
_serialNumber = 3578
# CA Issuer
class _issuer:
    _countryName = ASN1.EncodeASN1('VN')
    _stateOrProvinceName = ASN1.EncodeASN1('Hanoi')
    _localityName = ASN1.EncodeASN1('Hai Ba Trung')
    _organizationName = ASN1.EncodeASN1('MaDuc238')
    _organizationalUnitName = ASN1.EncodeASN1('Tai nang K64')
    _commonName = ASN1.EncodeASN1('Ma Duc')
    _emailAddress = ASN1.EncodeASN1('mavietduc@gmail.com')
# Validity
class _validity:
    _from = ut2dt('120822052654Z')
    _to = ut2dt('230821052654Z')
# User Subject
# class _subject:
#     _countryName = ASN1.EncodeASN1('VN')
#     _stateOrProvinceName = ASN1.EncodeASN1('Hanoi')
#     _organizationName = ASN1.EncodeASN1('DHBK')
#     _commonName = ASN1.EncodeASN1('User1')
# Public Key
# class _publicKeyInfo:
#     _algorithm = '1.2.840.113549.1.1.1'     # RSA
#     _parameters = b'\x05\x00'
#     _publickey = ASN1_RSAPublicKey(rsa.newkeys(2048)[0])
# Signature
class _signature:
    _algorithm = '1.2.840.113549.1.1.5'        # sha1RSA
    _parameters = b'\x05\x00'                  # sha1
############### end of modified #################

tbsCertificate = {
    'version': _version,
    'serialNumber': _serialNumber,
    'signature': {
        'algorithm': _signature._algorithm,
        'parameters': _signature._parameters
    },
    'issuer': (
        'rdnSequence',
        [
            [{'type': '2.5.4.6',
                'value': _issuer._countryName}],
            [{'type': '2.5.4.8',
                'value': _issuer._stateOrProvinceName}],
            [{'type': '2.5.4.7',
                'value': _issuer._localityName}],
            [{'type': '2.5.4.10',
                'value': _issuer._organizationName}],
            [{'type': '2.5.4.11',
                'value': _issuer._organizationalUnitName}],
            [{'type': '2.5.4.3',
                'value': _issuer._commonName}],
            [{'type': '1.2.840.113549.1.9.1',
                'value': _issuer._emailAddress}]
        ]
    ),
    'validity': {
        'notAfter': ('utcTime', _validity._to),
        'notBefore': ('utcTime', _validity._from)
    }
}

Client = socket.socket()
host = '127.0.0.1'
port = 443
print('Waiting for connection response')
try:
    Client.connect((host, port))
except socket.error as e:
    print(str(e))

def process_packet(source, data):
    print("Nhận tin từ", source)
    i = 0
    all_data = b''
    while i <= len(data):
        payload_len = int(data[i+3])*256+int(data[i+4])
        temp = data[5+i:5+payload_len+i]
        all_data += rsa.decrypt(temp, CApriv)

        i += 5 + payload_len
        if i >= len(data): break

    if data[0] == 1:
        rfc5280_der = asn1tools.compile_files(RFC5280_ASN_PATH, codec='der')
        UserInfo = rfc5280_der.decode('UserInfo', all_data)
        # print(UserInfo)
        
        try:
            tbsCertificate['subject'] = UserInfo['subject']
            tbsCertificate['subjectPublicKeyInfo'] = UserInfo['subjectPublicKeyInfo']
        except:
            print("Không thể tạo certificate")
            return
        
        encoded_TBSCertificate = foo_5280.encode('TBSCertificate', tbsCertificate)
        signature = rsa.sign(encoded_TBSCertificate, CApriv, 'SHA-1')

        data = {
            'tbsCertificate': tbsCertificate,
            'signatureAlgorithm': {
                'algorithm': _signature._algorithm,
                'parameters': _signature._parameters
            },
            'signature': (signature, len(signature)*8)
        }

        encoded = foo_5280.encode('Certificate', data)
        encoded = base64.b64encode(encoded)
        print(f"Cấp certificate cho User{source} thành công")
        # print(encoded)
        Client.send(b"\x02" + source.to_bytes(1, 'big') + b"\x02\x03\x00" + len(encoded).to_bytes(2, 'big') + encoded)

if __name__ == "__main__":
    res = Client.recv(65536)
    Client.send(b'rank=2')
    while True:
        res = Client.recv(65536)
        if len(res) > 2:
            process_packet(res[0], res[2:])

Client.close()