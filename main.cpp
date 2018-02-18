#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>

#include <unistd.h>
#include <signal.h>


namespace asio = boost::asio;
namespace fs = boost::filesystem;
using boost::asio::ip::tcp;

namespace
{

const int msgLength = 1024;

typedef std::shared_ptr<tcp::socket> SocketPtr;

std::string getPath(const std::string& request)
{
    std::istringstream sIn(request);
    std::string getWord, body;
    sIn >> getWord >> body;
    
    size_t paramsPos = body.find_first_of("?");
    std::string dir = body.substr(1, paramsPos);
    return dir;
}

std::string readFile(const fs::path& p)
{
    size_t len = fs::file_size(p);
    std::string res;
    res.resize(len, ' ');

    fs::ifstream fIn(p);
    fIn.read(&res[0], len);

    return res;
}

struct Session
{
    Session(SocketPtr s)
        : s(s)
    {}

    void operator()()
    {
        try
        {
            char buf[msgLength];
            for (;;) {
                boost::system::error_code err;
                size_t len = s->read_some(asio::buffer(buf), err);
                if (err == asio::error::eof)
                    break;
                else if (err)
                    throw boost::system::system_error(err);
                
                std::string filePath = getPath(buf);
                std::string response = getResponse(filePath);
                //std::cerr << response << std::endl;
                asio::write(*s, asio::buffer(response.c_str(), response.size()));
            }   
        }
        catch (std::exception& e)
        {
        }
    }

    static std::string getResponse(const fs::path& filePath)        
    {
        if (!fs::exists(filePath) || !fs::is_regular_file(filePath))
            return notFound();

        std::string html = readFile(filePath);
        std::ostringstream sOut;
        sOut << "HTTP/1.0 200 OK" << std::endl
             << "Content-length:" << html.size() << std::endl
             << "Content-Type: text/html" << std::endl
             << std::endl << html;

        return sOut.str();
    }

    static std::string notFound()
    {
        std::ostringstream sOut;
        sOut << "HTTP/1.0 404 NOT FOUND" << std::endl
             << "Content-length:" << 0 << std::endl
             << "Content-Type: text/html" << std::endl << std::endl;
        return sOut.str();
    }

private :
    SocketPtr s;
};

struct Server
{
    void run(asio::io_service& io_service, const std::string& ip, short port)
    {
        tcp::acceptor a(io_service, tcp::endpoint(/*tcp::v4()*/asio::ip::address::from_string(ip), port));
        for (;;) {
            SocketPtr s(new tcp::socket(io_service));
            a.accept(*s);
            Session session(s);
            std::thread t(session);
            t.detach();
        }
    }
};

void summonDaemon()
{
    pid_t pid = fork();
    if (pid < 0)
        exit(1);

    if (pid > 0)
        exit(0);

    if (setsid() < 0)
        exit(1);

    signal(SIGCHLD, SIG_IGN);    
    signal(SIGHUP, SIG_IGN);

    pid = fork();

    if (pid < 0)
        exit(1);

    if (pid > 0)
        exit(0);

    umask(0);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

} // namespace

int main(int argc, char **argv)
{
    summonDaemon();

    short port = 5001;
    std::string ip("127.0.0.1");
    std::string dir("1");

    int switchName;
    while ((switchName = getopt(argc, argv, "h:p:d:")) != -1) {
        switch(switchName) {
            case 'h':
                ip = std::string(optarg);
                break;
            case 'p':
                port = std::atoi(optarg);
                break;
            case 'd':
                dir = std::string(optarg);
                break;
            default: {
                std::cerr << "Unknown cmd arg" << std::endl;
            }    
        }
    }

    fs::path cur_path(dir);
    fs::current_path(cur_path);
    asio::io_service service;
    Server server;
    server.run(service, ip, port);
    return 0;
}
