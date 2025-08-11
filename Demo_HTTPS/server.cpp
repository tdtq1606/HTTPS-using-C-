#include "https_tcpserver.h"

int main()
{
    using namespace https;

    TcpServer server = TcpServer("127.0.0.1", 443);
	cout << "Starting server..." << endl;
    server.startListen();

    return 0;
}