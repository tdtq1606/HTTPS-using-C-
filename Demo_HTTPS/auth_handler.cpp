#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "https_tcpserver.h"
#include <iostream>
#include <sstream>
#include <regex>
#include <map>
#include <fstream>

#include <openssl/evp.h> // OpenSSL for AES encryption
#include <openssl/rand.h> // OpenSSL for random IV generation
#include <sstream>
#include <iomanip>
#include <vector>

// Helper: convert bytes to hex string
string toHex(const vector<unsigned char>& data) {
    ostringstream oss;
    for (unsigned char byte : data)
        oss << hex << setw(2) << setfill('0') << (int)byte;
    return oss.str();
}

// Helper: convert hex string to bytes
vector<unsigned char> fromHex(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
        bytes.push_back((unsigned char)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    return bytes;
}

// AES encryption
string aesEncrypt(const string& plaintext, const string& key) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.data(), iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    string ivHex = toHex(vector<unsigned char>(iv, iv + sizeof(iv)));
    string ctHex = toHex(ciphertext);

    return ivHex + ":" + ctHex;
}

// AES decryption
string aesDecrypt(const string& cipherHexWithIV, const string& key) {
    size_t sep = cipherHexWithIV.find(':');
    if (sep == string::npos) return "";

    vector<unsigned char> iv = fromHex(cipherHexWithIV.substr(0, sep));
    vector<unsigned char> ciphertext = fromHex(cipherHexWithIV.substr(sep + 1));

    vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, plaintext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
}



namespace https
{
    // Phương thức để lưu thông tin người dùng vào file
    void TcpServer::saveUsersToFile(const string& filename)
    {
        ofstream file(filename, ios::out | ios::trunc);
        if (!file.is_open())
        {
            cerr << "Error: Could not open file for writing: " << filename << endl;
            return;
        }

        for (const auto& user : m_users)
        {
            string encryptedPass = aesEncrypt(user.second, m_encryptionKey);
            file << user.first << "," << encryptedPass << endl;
        }

        file.close();
    }


    // Phương thức để đọc thông tin người dùng từ file
    void TcpServer::loadUsersFromFile(const string& filename)
    {
        ifstream file(filename);
        if (!file.is_open())
        {
            cerr << "Warning: Could not open file for reading: " << filename << endl;
            return;
        }

        m_users.clear();
        string line;
        while (getline(file, line))
        {
            size_t commaPos = line.find(',');
            if (commaPos != string::npos)
            {
                string username = line.substr(0, commaPos);
                string encryptedPass = line.substr(commaPos + 1);
                string decryptedPass = aesDecrypt(encryptedPass, m_encryptionKey);

                m_users[username] = decryptedPass;
            }
        }

        file.close();
    }

    // Phân tích dữ liệu biểu mẫu từ yêu cầu POST
    map<string, string> TcpServer::parseFormData(const string& request)
    {
        map<string, string> formData;

        // Tìm phần thân của yêu cầu (sau dòng trống)
        size_t bodyPos = request.find("\r\n\r\n");
        if (bodyPos == string::npos)
            return formData;

        string body = request.substr(bodyPos + 4);

        // Phân tích các cặp key-value
        istringstream iss(body);
        string pair;

        while (getline(iss, pair, '&'))
        {
            size_t pos = pair.find('=');
            if (pos != string::npos)
            {
                string key = pair.substr(0, pos);
                string value = pair.substr(pos + 1);

                // Giải mã URL encoding (đơn giản)
                string decodedValue;
                for (size_t i = 0; i < value.length(); ++i)
                {
                    if (value[i] == '+')
                        decodedValue += ' ';
                    else if (value[i] == '%' && i + 2 < value.length())
                    {
                        int hex = stoi(value.substr(i + 1, 2), nullptr, 16);
                        decodedValue += static_cast<char>(hex);
                        i += 2;
                    }
                    else
                        decodedValue += value[i];
                }

                formData[key] = decodedValue;
            }
        }

        return formData;
    }

    string TcpServer::handleLogin(const map<string, string>& formData)
    {
        // Xử lý đăng nhập
        auto usernameIt = formData.find("username");
        auto passwordIt = formData.find("password");

        if (usernameIt != formData.end() && passwordIt != formData.end())
        {
            string username = usernameIt->second;
            string password = passwordIt->second;

            auto userIt = m_users.find(username);
            if (userIt != m_users.end() && userIt->second == password)
            {
                // Login successful
                return buildHtmlResponse(getHomePage(username));
            }
        }

        // Login failed
        return buildHtmlResponse(getLoginPage() + "<script>alert('Login failed. Please check your username and password.');</script>");
    }

    // Xử lý đăng ký
    string TcpServer::handleRegister(const map<string, string>& formData)
    {
        auto usernameIt = formData.find("username");
        auto passwordIt = formData.find("password");
        auto confirmPasswordIt = formData.find("confirm_password");

        if (usernameIt != formData.end() && passwordIt != formData.end() && confirmPasswordIt != formData.end())
        {
            string username = usernameIt->second;
            string password = passwordIt->second;
            string confirmPassword = confirmPasswordIt->second;

            if (password != confirmPassword)
            {
                return buildHtmlResponse(getRegisterPage() + "<script>alert('Password confirmation does not match!');</script>");
            }

            if (m_users.find(username) != m_users.end())
            {
                return buildHtmlResponse(getRegisterPage() + "<script>alert('Username already exists!');</script>");
            }

            // Registration successful
            m_users[username] = password;

            // Lưu thông tin người dùng vào file
            saveUsersToFile("users.csv");

            return buildHtmlResponse(getLoginPage() + "<script>alert('Registration successful! Please login.');</script>");
        }

        // Registration failed
        return buildHtmlResponse(getRegisterPage() + "<script>alert('Registration failed. Please fill in all required information.');</script>");
    }
    // Lấy phương thức HTTP từ yêu cầu
    string TcpServer::getRequestMethod(const string& request)
    {
        istringstream iss(request);
        string method;
        iss >> method;
        return method;
    }

    // Lấy đường dẫn từ yêu cầu
    string TcpServer::getRequestPath(const string& request)
    {
        istringstream iss(request);
        string method, path;
        iss >> method >> path;
        return path;
    }

    // Xử lý yêu cầu HTTP
    string TcpServer::handleRequest(const string& request)
    {
        string method = getRequestMethod(request);
        string path = getRequestPath(request);

        cout << "Method: " << method << ", Path: " << path << endl;

        if (path == "/" || path == "/index.html")
        {
            return buildHtmlResponse(getLoginPage());
        }
        else if (path == "/register" && method == "GET")
        {
            return buildHtmlResponse(getRegisterPage());
        }
        else if (path == "/login" && method == "POST")
        {
            auto formData = parseFormData(request);
            return handleLogin(formData);
        }
        else if (path == "/register" && method == "POST")
        {
            auto formData = parseFormData(request);
            return handleRegister(formData);
        }
        else if (path == "/logout")
        {
            return buildHtmlResponse(getLoginPage());
        }
        else
        {
            return buildHtmlResponse("<h1>404 Not Found</h1><p>The requested page was not found.</p>", 404);
        }
    }

    // Tạo phản hồi HTML
    string TcpServer::buildHtmlResponse(const string& content, int statusCode)
    {
        string statusText = (statusCode == 200) ? "OK" : "Not Found";
        ostringstream ss;
        ss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
        ss << "Content-Type: text/html; charset=UTF-8\r\n";
        ss << "Content-Length: " << content.length() << "\r\n";
        ss << "\r\n";
        ss << content;
        return ss.str();
    }
}