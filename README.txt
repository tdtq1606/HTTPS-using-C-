

Cài đặt openssl (Lưu ý chỉ hoạt động trên Windows và chip Intel):
	- https://slproweb.com/products/Win32OpenSSL.html
	- Kiểm tra bằng: openssl version
	- Đường dẫn đề nghị: C:\OpenSSL-Win64
	* Lưu ý: Nếu đổi đường dẫn thì có thể dẫn đến lỗi vì trong function startServer đã hardcode đường dẫn là
		C:/OpenSSL-Win64/tests/certs/servercert.pem", SSL_FILETYPE_PEM
		C:/OpenSSL-Win64/tests/certs/serverkey.pem", SSL_FILETYPE_PEM
	- Thêm vào Path (nếu chưa thêm): bật start -> edit the system environment variables -> Environment variables -> System variables -> Path, thêm C:\OpenSSL-Win64\bin.

Cài đặt thư viện openssl vào visual studio:
1. Vào solution explorer -> properties -> C/C++ -> General -> Additional Include Directories: nhập C:\OpenSSL-Win64\include (Đường dẫn đến nơi openssl được cài đặt)
2. Tương tự trong properties -> Linker -> General -> Additional Library Directories nhập: C:\OpenSSL-Win64\lib\VC\x64\MD (đường dẫn đến nơi chứa certificate)
3. Tương tự trong properties -> Linker -> Input -> Additional Depenedencies nhập (Đường dẫn đến nơi chứa thư viện):
libssl.lib
libcrypto.lib

1. Tạo chứng chỉ gốc (Root CA):
	- Mở PowerShell, di chuyển về thư mục C:\OpenSSL-Win64\tests\certs (cd C:\OpenSSL-Win64\tests\certs) và chạy: openssl genrsa -out rootCA.key 2048
	- openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem, có thể nhập như sau:
		Country Name (VN): VN
		State or Province Name: HCM
		Locality Name: HCM
		Organization Name: HCMUS
		Common Name (CN): Test

2. Tạo Server certificate và Key:
	- openssl genrsa -out serverkey.pem 2048
	- Tạo file openssl_san.cnf với nội dung:

[ req ]
default_bits       = 2048
prompt            = no
default_md        = sha256
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[ req_distinguished_name ]
C  = VN
ST = HCM
L  = HCM
O  = HCMUS
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1   = localhost
IP.1    = 127.0.0.1

	- cd về thư mục chứa file .cnf
	- Tạo CSR bằng SAN config: openssl req -new -key serverkey.pem -out server.csr -config openssl_san.cnf 
	- Ký chứng chỉ với Root CA: openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out servercert.pem -days 500 -sha256 -extfile openssl_san.cnf -extensions v3_req

3. Cài đặt chứng chỉ vào Windows:
	- cd về thư mục chứa các file chứng chỉ (cd C:\OpenSSL-Win64\tests\certs)
	- Thêm Root CA vào Trusted Root Certification: certutil -addstore root rootCA.pem
	- Kiểm tra chứng chỉ: openssl x509 -text -noout -in servercert.pem


Cách chạy code: chạy code bình thường sau khi đã cài đặt các yêu cầu nêu trên.
Lưu ý: Nếu đã bật 1 localhost thì phải tắt nó đi trước khi chạy code này, vì không thể mở 2 localhost cùng 1 port.
Công cụ hỗ trợ: WireShark để kiểm tra gói tin gửi đi và nhận về.