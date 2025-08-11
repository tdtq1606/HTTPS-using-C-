// https_tcpserver.h
#ifndef INCLUDED_HTTPS_TCPSERVER
#define INCLUDED_HTTPS_TCPSERVER

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h> // OpenSSL for HTTPS support
#include <openssl/err.h> // OpenSSL error handling
#include <string>
#include <sstream>
#include <map>

using namespace std;

const string m_encryptionKey = "my_secret_key_1234567890123456"; // 32 bytes for AES-256

#pragma comment(lib, "Ws2_32.lib") // Winsock Library for MSVC

namespace https
{
    class TcpServer
    {
    public:
        TcpServer(string ip_address, int port);
        ~TcpServer();
        void startListen();

    private:
        std::string m_ip_address;
        int m_port;
        SOCKET m_socket;
        SOCKET m_new_socket;
        struct sockaddr_in m_socketAddress;
        int m_socketAddress_len;
        string m_serverMessage;
        map<string, string> m_users; // Lưu trữ thông tin người dùng (username, password)

        WSADATA m_wsaData;
        SSL_CTX* m_sslCtx;
        SSL* m_ssl;

        static void ssl_info_callback(const SSL*, int, int);
        int startServer();
        void closeServer();
        void acceptConnection(SOCKET& new_socket);
        void sendResponse();
        string buildResponse();

        // Các phương thức lưu trữ dữ liệu
        void saveUsersToFile(const string& filename);
        void loadUsersFromFile(const string& filename);

        // Các phương thức xử lý yêu cầu HTTP
        string handleRequest(const string& request);
        string getRequestPath(const string& request);
        string getRequestMethod(const string& request);
        map<string, string> parseFormData(const string& request);

        // Các phương thức xử lý đăng nhập và đăng ký
        string handleLogin(const map<string, string>& formData);
        string handleRegister(const map<string, string>& formData);

        // Các phương thức tạo trang HTML
        string buildHtmlResponse(const string& content, int statusCode = 200);
        string getLoginPage();
        string getRegisterPage();
        string getHomePage(const string& username);
    };
} // namespace https

#endif