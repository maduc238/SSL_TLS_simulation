# SSL/TLS simulation
Mô phỏng hệ thống giao thức mạng bảo mật SSL/TLS, cấp chứng chỉ X.509 và giao tiếp bảo mật

![image](https://user-images.githubusercontent.com/95759699/220095451-4757e6ed-d8c3-42ff-bb2d-939f2a46410b.png)

# Requirement
Chạy trên Python3 với yêu cầu các thư viện:
```
pip install asn1tools rsa pycrypto pycryptodome
```

# Mô hình hệ thống
Trong project này sẽ có 4 môi trường chính:
- Internet: `internet.py` là nơi thiết lập kết nối, giao tiếp giữa các thiết bị khác
- Certificate Authority server: `CA.py` server xác thực người dùng và cung cấp chứng chỉ
- Client 0, 1: `client0.py` và `client1.py` là hai người dùng cần được cấp chứng chỉ và giao tiếp với nhau

Luồng giao tiếp giữa hai thiết bị qua giao thức SSL/TLS:
```
User 0                            User 1
  | --- ClientHello --------------> |
  |                                 |
  | <-------------- ServerHello --- |
  |                                 |
  | <-------------- Certificate --- |
  | <-------- ServerKeyExchange --- |
  | <------- CertificateRequest --- |
  | <---------- ServerHelloDone --- |
  |                                 |
  | --- Certificate --------------> |
  | --- ClientKeyExchange --------> |
  | --- CertificateVerify --------> |
  |                                 |
  | --- ChangeCipherSpec ---------> |
  | --- Finished -----------------> |
  |                                 |
  | <--------- ChangeCipherSpec --- |
  | <----------------- Finished --- |
```

# Cấu hình
Địa chỉ IP `host` của các thiết bị phải gọi đúng địa chỉ IP của Internet

# Chạy mô phỏng
Đầu tiên `internet.py` phải được chạy trước

Khi Internet chạy thành công, sau đó mới chạy code các thiết bị khác

Những bước chi tiết, công đoạn sau sẽ được hướng dẫn trên terminal của mỗi thiết bị
