import socket
import rsa
import platform
from common_func import *
from asn1 import ASN1
from _thread import *

pub = rsa.PublicKey(23680480736666663855187329778699693569337273817387127956965619425569733107480648718015109407589481269924650818273297358490043689483044855372214541332248964091939683292387662982871291404818957150850582804077264925023124934078755489190472542627142472112010463568191981151070355104201512199866114050453399084285876193380516256494065623422367118684744005536901395594726933303287638415720925109039200343067752339887371553382638138773076661149449859989411468827980289922894829683261188548830812218228307632176671574688521875088791809104384416257422422756892915850004907161377806282559494960271060907671070387283565436637603, 65537)
pirv = rsa.PrivateKey(23680480736666663855187329778699693569337273817387127956965619425569733107480648718015109407589481269924650818273297358490043689483044855372214541332248964091939683292387662982871291404818957150850582804077264925023124934078755489190472542627142472112010463568191981151070355104201512199866114050453399084285876193380516256494065623422367118684744005536901395594726933303287638415720925109039200343067752339887371553382638138773076661149449859989411468827980289922894829683261188548830812218228307632176671574688521875088791809104384416257422422756892915850004907161377806282559494960271060907671070387283565436637603, 65537, 18594400402667244284172226036310251167610135464189068645092203507320201343425266089045509334024479235112874494700125964955004627988570903494354830271432380809852572469132879514801402673045582708087368077278791069267971256429602151902450638816781036015627362645264927323729062117846621287473808151696979333366657032119631301725425394012827803916903960280600751833348368643410785681065164934789674415625865185541056165665283211609385659069589922288077594325121352634699877793367118503895465738224803788251973387141778386609266110998060006866902039578519067973077710345315032027544701539250612767068558641200442398538033, 2703606859902366949434967714006149399767906967568769327485243445983804061712680488505868405916955745124635214768562086772245543874660724458926677499432786348133728319079355067481754880014124618229849151948010772801649860754067478602048351826744501739065642047611356301453429713478855341903541473442959344144547475301152881152411, 8758847703738189536898059714710265604913008263966990430701951091050385545020558301496310722379275155480157209728024905463409281651598705312495899924142778858922723379090783498735208170657926864865275421868385204193453765432738931937072308066626384405645393750481445080085266613037815915673)

CApub  = rsa.PublicKey (29168623252785354452421324498503678015422860934849817475337334239651001217600025701418638724474809721158682729632678713367350325701797899817595268765817603327654164254517390206298518001824346346391367670978938422966272870497577718801862098155093820779848076938401205806480088038123682253549446041222767223681871209891946128254636808798151098615544414964770715346189578688461190409759116813541808230291779930361178504809848269543566367990765566457122439886866444699616707117850663902857968796931852736598651991750138190478951216862736262267274704391647618393262609912618490112016814640215008996979887749607944860028803, 65537)

Client = socket.socket()
host = '127.0.0.1'
port = 443
print('Waiting for connection response')
try:
    Client.connect((host, port))
except socket.error as e:
    print(str(e))

MyCer = None
PartnerCer = None

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
                    'algorithm': '1.2.840.113549.1.1.1',     # RSA
                    'parameters': b'\x05\x00'
                },
                'subjectPublicKey': ASN1_RSAPublicKey(pub)
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

def process_packet(source, data):
    print("Nhận tin từ", source)
    i = 0
    all_data = []
    content_type = []
    while i <= len(data):
        payload_len = int(data[i+3])*256+int(data[i+4])
        temp = data[5+i:5+payload_len+i]
        all_data.append(temp)
        content_type.append(data[i])

        i += 5 + payload_len
        if i >= len(data): break
    
    for (itr,content) in enumerate(content_type):
        if content == 2:
            # print(all_data)
            all_data = b''.join(all_data)
            try:
                CerPem = Certificate_PEM(all_data, CApub)
                if CerPem.valid:
                    global MyCer
                    MyCer = all_data
                    print('My certificate valid: ')
                    PrintCertificate(MyCer)
                else:
                    return
            except:
                print("Input không hợp lệ")

        if content == 21:   # alert
            if b'no_certificate' in all_data:
                print('Partner không có certificate')
            if b'bad_certificate' in all_data:
                print('Certificate của partner không an toàn') 

        if content == 22:   # handshake
            # print(all_data)
            if all_data[itr] == b'client_hello':
                reponse = b'server_hello'
                message = b"\x01" + source.to_bytes(1, 'big') + b"\x16\x03\x00" + len(reponse).to_bytes(2, 'big') + reponse
                Client.send(message)
            elif all_data[itr] == b'certificate_request':
                if MyCer == None:
                    reponse = b'no_certificate'
                    if platform.system() == 'Linux':
                        message = b"\x15\x03\x00" + len(reponse).to_bytes(2, 'big') + reponse
                    elif platform.system() == 'Windows':
                        message = b"\x01" + source.to_bytes(1, 'big') + b"\x15\x03\x00" + len(reponse).to_bytes(2, 'big') + reponse
                    else:
                        return
                    Client.send(message)
                    print("No certificate")
                else:
                    reponse = b'certificate'
                    if platform.system() == 'Linux':
                        message = b"\x16\x03\x00" + len(reponse).to_bytes(2, 'big') + reponse
                    elif platform.system() == 'Windows':
                        message = b"\x01" + source.to_bytes(1, 'big') + b"\x16\x03\x00" + len(reponse).to_bytes(2, 'big') + reponse
                    else:
                        return
                    message += b"\x16\x03\x00" + len(MyCer).to_bytes(2, 'big') + MyCer
                    Client.send(message)
            elif all_data[itr] == b'certificate':
                print('Nhận certificate từ server',source)
                try:
                    server_cer = all_data[itr+1]
                    CerPem = Certificate_PEM(server_cer, CApub)
                    if CerPem.valid:
                        global PartnerCer
                        PartnerCer = server_cer
                        print('Partner certificate valid: ')
                        PrintCertificate(PartnerCer)
                    else:
                        return
                except:
                    message = b'bad_certificate'
                    print("Có lỗi xảy ra trong quá trình thực hiện")
                    Client.send( b"\x01" + source.to_bytes(1, 'big') + b"\x15\x03\x00" + len(message).to_bytes(2, 'big') + message)
                    return
                break

        
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
    

if __name__ == "__main__":
    res = Client.recv(1024)
    Client.send(b'rank=1')
    Client.send
    start_new_thread(InputAction, ())
    while True:
        res = Client.recv(65536)
        if len(res) > 2:
            process_packet(res[0], res[2:])

    # Client.close()