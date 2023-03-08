import socket
import rsa
import platform
from common_func import *
from asn1 import ASN1
from _thread import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

host = '127.0.0.1'

############### key #################
### RSA
pub = rsa.PublicKey(23680480736666663855187329778699693569337273817387127956965619425569733107480648718015109407589481269924650818273297358490043689483044855372214541332248964091939683292387662982871291404818957150850582804077264925023124934078755489190472542627142472112010463568191981151070355104201512199866114050453399084285876193380516256494065623422367118684744005536901395594726933303287638415720925109039200343067752339887371553382638138773076661149449859989411468827980289922894829683261188548830812218228307632176671574688521875088791809104384416257422422756892915850004907161377806282559494960271060907671070387283565436637603, 65537)
priv = rsa.PrivateKey(23680480736666663855187329778699693569337273817387127956965619425569733107480648718015109407589481269924650818273297358490043689483044855372214541332248964091939683292387662982871291404818957150850582804077264925023124934078755489190472542627142472112010463568191981151070355104201512199866114050453399084285876193380516256494065623422367118684744005536901395594726933303287638415720925109039200343067752339887371553382638138773076661149449859989411468827980289922894829683261188548830812218228307632176671574688521875088791809104384416257422422756892915850004907161377806282559494960271060907671070387283565436637603, 65537, 18594400402667244284172226036310251167610135464189068645092203507320201343425266089045509334024479235112874494700125964955004627988570903494354830271432380809852572469132879514801402673045582708087368077278791069267971256429602151902450638816781036015627362645264927323729062117846621287473808151696979333366657032119631301725425394012827803916903960280600751833348368643410785681065164934789674415625865185541056165665283211609385659069589922288077594325121352634699877793367118503895465738224803788251973387141778386609266110998060006866902039578519067973077710345315032027544701539250612767068558641200442398538033, 2703606859902366949434967714006149399767906967568769327485243445983804061712680488505868405916955745124635214768562086772245543874660724458926677499432786348133728319079355067481754880014124618229849151948010772801649860754067478602048351826744501739065642047611356301453429713478855341903541473442959344144547475301152881152411, 8758847703738189536898059714710265604913008263966990430701951091050385545020558301496310722379275155480157209728024905463409281651598705312495899924142778858922723379090783498735208170657926864865275421868385204193453765432738931937072308066626384405645393750481445080085266613037815915673)
CApub  = rsa.PublicKey (29168623252785354452421324498503678015422860934849817475337334239651001217600025701418638724474809721158682729632678713367350325701797899817595268765817603327654164254517390206298518001824346346391367670978938422966272870497577718801862098155093820779848076938401205806480088038123682253549446041222767223681871209891946128254636808798151098615544414964770715346189578688461190409759116813541808230291779930361178504809848269543566367990765566457122439886866444699616707117850663902857968796931852736598651991750138190478951216862736262267274704391647618393262609912618490112016814640215008996979887749607944860028803, 65537)

### ECC
priv_ECC = 543216205833251
pub_ECC = g_point.multiply(priv_ECC)
CApub_ECC = Point(35801561847477176246370884757282389895181578807771762541197903235389839145488, 108677721235675508677044546376599977768226960963466748268417198848443123645579, secp256k1_curve_config)
############### key #################

MyCer = None
PartnerCer = None
ExchangeFlag = False

AES128_key = None

BlockCipherStat = False

UserInfo = {
            'subject': (
                'rdnSequence',
                [
                    [{'type': '2.5.4.6',
                        'value': ASN1.EncodeASN1('VN')}],
                    [{'type': '2.5.4.8',
                        'value': ASN1.EncodeASN1('Hanoi')}],
                    [{'type': '2.5.4.10',
                        'value': ASN1.EncodeASN1('DHBK')}],
                    [{'type': '2.5.4.3',
                        'value': ASN1.EncodeASN1('User1')}]
                ]
            ),
            'subjectPublicKeyInfo': {
                'algorithm': {
                    # 'algorithm': '1.2.840.113549.1.1.1',     # RSA
                    # 'parameters': b'\x05\x00'

                    'algorithm': '1.2.840.10045.2.1',     # ecPublicKey
                    'parameters': b'\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07'

                },
                # 'subjectPublicKey': ASN1_RSAPublicKey(pub)    # RSA
                'subjectPublicKey': ASN1_ECDSAPublicKey(pub_ECC)    # ECDSA
            }
        }

UserInfodata = foo_5280.encode('UserInfo', UserInfo)

def Certificate_Requirement(CApub):
    chunks = [UserInfodata[i:i+245] for i in range(0, len(UserInfodata), 245)]
    return [rsa.encrypt(c, CApub) for c in chunks]

def Action1(dest):
    user_data = Certificate_Requirement(CApub)
    data = b"\x01" + dest
    for chunk in user_data:
        data += b"\x01\x03\x00" + len(chunk).to_bytes(2, 'big') + chunk
    Client.send(data)

def process_packet(source, dest, datas):
    print("Nhận tin từ", source)
    global PartnerCer
    i = 0
    all_data = []
    content_type = []
    while i <= len(datas):
        payload_len = int(datas[i+3])*256+int(datas[i+4])
        temp = datas[5+i:5+payload_len+i]
        all_data.append(temp)
        content_type.append(datas[i])

        i += 5 + payload_len
        if i >= len(datas): break
    
    send_data = dest.to_bytes(1, 'big') + source.to_bytes(1, 'big')
    for content,data in zip(content_type, all_data):
        if content == 2:
            all_datas = b''.join(all_data)
            try:
                CerPem = Certificate_PEM(all_datas, CApub_ECC)
                if CerPem.valid:
                    global MyCer
                    MyCer = all_datas
                    print('My certificate valid: ')
                    PrintCertificate(MyCer)
                else:
                    print('My certificate không hợp lệ')
            except:
                print("Input không hợp lệ")

        if content == 20:   # ChangeCipherSpec
            try:
                global AES128_key
                decoded = foo_3279.decode('Duc-Encode', data)
                Cm = (Point(decoded['ax'], decoded['ay'], secp256k1_curve_config), Point(decoded['bx'], decoded['by'], secp256k1_curve_config))
                AES128_key_point = ECC_decode(Cm, priv_ECC)
                AES128_key = (AES128_key_point.x % 2**128).to_bytes(16, 'big')
                print('Mã hóa khối key =',AES128_key)
                # Finished
                payload = b'\x14\x00\x00'           # Finished
                send_data += b'\x16\x03\x00' + len(payload).to_bytes(2, 'big') + payload

            except:
                print("Không thể giải mã được AES128 key")

        if content == 21:   # alert
            level = ''
            if data[0] == 1:
                level = 'Warning: '
            if data[0] == 2:
                level = 'Fatal: '

            if data[1] == 41:
                print(level+'Partner không có certificate')
            if data[1] == 42:
                print(level+'Partner đọc Certificate bị gián đoạn') 

        if content == 22:   # handshake
            mess_type, handshake_mess = ReadHandshakeMessageData(data)
            for _type, _mess in zip(mess_type, handshake_mess):
                if _type == 1:
                    print("ClientHello")
                    # ServerHello
                    payload = b'\x02\x00\x00'
                    # Certificate
                    if MyCer != None:
                        payload += b'\x0b' + len(MyCer).to_bytes(2, 'big') + MyCer
                    # ServerKeyExchange
                    payload += b'\x0c\x00\x00'
                    # CertificateRequest
                    if PartnerCer == None:
                        payload += b'\x0d\x00\x00'
                    # ServerHelloDone
                    payload += b'\x0e\x00\x00'

                    send_data += b"\x16\x03\x00" + len(payload).to_bytes(2, 'big') + payload
                    if MyCer == None:
                        payload = b'\x01\x29'
                        send_data += b"\x15\x03\x00" + len(payload).to_bytes(2, 'big') + payload

                if _type == 11: # Certificate
                    print('Nhận certificate từ server',source)
                    try:
                        server_cer = _mess
                        CerPem = Certificate_PEM(server_cer, CApub_ECC)
                        if CerPem.valid:
                            # global PartnerCer
                            PartnerCer = server_cer
                            print('Partner certificate valid: ')
                            PrintCertificate(PartnerCer)
                        else:
                            print('Partner certificate không hợp lệ: ')
                    except:
                        print("Có lỗi xảy ra trong quá trình thực hiện")
                if _type == 15: # CertificateVerify
                    print('CertificateVerify')
                if _type == 16: # ClientKeyExchange
                    print('ClientKeyExchange')
                    global ExchangeFlag
                    ExchangeFlag = True
                if _type == 20: # Finished
                    print("Finished")
                    global BlockCipherStat
                    BlockCipherStat = True

        if content == 23:   # Application
            try:
                cipher = AES.new(AES128_key, AES.MODE_ECB)
                pt = unpad(cipher.decrypt(data), AES.block_size)
                print("Bản tin nhận được là: ", pt)
            except (ValueError, KeyError):
                print("Lỗi trong quá trình giải mã AES128")
    
    if len(send_data) > 2:
        Client.send(send_data)
        
def InputAction():
    while True:
        print("***********************************************")
        Input = input('Take Action:\n1. Require certificate\n2. Show my certificate\n3. Show partner certificate\n')
        if Input == '1':
            Action1(b'\x02')
        if Input == '2':
            if MyCer == None:
                print("Chưa có certificate, cần gửi yêu cầu tới CA")
            else:
                print('My certificate: ')
                PrintCertificate(MyCer)
        if Input == '3':
            if PartnerCer == None:
                print("Partner chưa có certificate, cần thiết lập handshake")
            else:
                print('Partner certificate: ')
                PrintCertificate(PartnerCer)
        else:
            continue

Client = socket.socket()
port = 443
print('Waiting for connection response')
try:
    Client.connect((host, port))
except socket.error as e:
    print(str(e))

if __name__ == "__main__":
    res = Client.recv(1024)
    Client.send(b'rank=1')
    Client.send
    start_new_thread(InputAction, ())
    while True:
        res = Client.recv(65536)
        if len(res) > 2:
            process_packet(res[0], res[1], res[2:])

    # Client.close()