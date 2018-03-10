#include <string>
#include <cstring>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <deque>
#include <vector>
#include <fstream>
#include <future>
#include <mutex>
#include <thread>
#include <chrono>
#include <functional>
#include <ctime>
#include <ratio>

#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <sys/types.h>
#include <net/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <iomanip>
#include <sys/uio.h>

namespace Sockets
{
    class Socket {
    public:
        Socket(int socket_fd) : socket_fd(socket_fd) {
            if(socket_fd < 0)
                throw std::runtime_error((std::string("Creating socket error: ") + strerror(errno)).c_str());
        }

        Socket& operator=(Socket&& s) noexcept {
            socket_fd = s.socket_fd;
            s.socket_fd = -1;
            return *this;
        }

        Socket(Socket&& s) noexcept : socket_fd(s.socket_fd) {
            s.socket_fd = -1;
        }

        Socket(const Socket&) = delete;
        Socket& operator= (const Socket&) = delete;

        virtual ~Socket() {
            if (socket_fd > 0)
                close(socket_fd);
        }

        operator int() {
            return socket_fd;
        }

    protected:
        int socket_fd;
    };

    class RawSocket : public Socket {
    public:
        RawSocket(const std::string& interface, uint16_t ethertype = ETH_P_ALL) :
                Socket(socket(AF_PACKET, SOCK_RAW, htons(ethertype))),
                                                  interface_name(interface) {

            if(setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), socklen_t(interface.length())))
                throw std::runtime_error((std::string("Binding to ") + interface + " failed: " + strerror(errno)).c_str());

            ifreq if_req{};
            memset(&if_req, 0, sizeof(if_req));
            memcpy(if_req.ifr_name, interface.c_str(), std::min(size_t(sizeof(if_req.ifr_name)),
                                                                size_t(interface.length())));
            if(ioctl(socket_fd, SIOCGIFINDEX, &if_req) == -1) {
                throw std::runtime_error((std::string("Getting index for ") + interface + " failed: "
                                          + strerror(errno)).c_str());
            }

            sockaddr_ll addr{};
            memset(&addr, 0, sizeof(sockaddr_ll));
            addr.sll_protocol = htons(ethertype);
            addr.sll_family = AF_PACKET;
            addr.sll_ifindex = if_req.ifr_ifindex;

            if(bind(socket_fd, (sockaddr*)(&addr), sizeof(addr))) {
                if(errno == ENETDOWN)
                    throw std::runtime_error(std::string("Interface ") + interface + " is down.");
                else
                    throw std::runtime_error(std::string("Cannot bind socket to interface ") + interface + ": "
                                             + strerror(errno));
            }

            memset(&if_req, 0, sizeof(if_req));
            memcpy(if_req.ifr_name, interface.c_str(), std::min(size_t(sizeof(if_req.ifr_name)),
                                                                size_t(interface.length())));
            if(ioctl(socket_fd, SIOCGIFFLAGS, &if_req) == -1) {
                throw std::runtime_error((std::string("Getting flags for ") + interface + " failed: "
                                          + strerror(errno)).c_str());
            }

            if((if_req.ifr_flags & IFF_PROMISC) == 0) {
                if_req.ifr_flags |= IFF_PROMISC;
                if(ioctl(socket_fd, SIOCSIFFLAGS, &if_req) == -1) {
                    throw std::runtime_error((std::string("Activation of promisc mode for ") + interface + " failed: "
                                              + strerror(errno)).c_str());
                }
            }
        }

        RawSocket(RawSocket&& s) noexcept : Socket(std::move(s)), interface_name(std::move(s.interface_name)) {}

        RawSocket& operator=(RawSocket&& s) noexcept {
            interface_name = std::move(s.interface_name);
            Socket::operator=(std::move(s));
            return *this;
        }

        ~RawSocket() override {
            ifreq if_req{};
            memset(&if_req, 0, sizeof(if_req));
            memcpy(if_req.ifr_name, interface_name.c_str(), std::min(size_t(sizeof(if_req.ifr_name)),
                                                                     size_t(interface_name.length())));

            if(ioctl(socket_fd, SIOCGIFFLAGS, &if_req) == -1) {
                std::cerr << "Getting flags for " << interface_name << " failed: " << strerror(errno) << std::endl;
            }

            if((if_req.ifr_flags & IFF_PROMISC) != 0) {
                if_req.ifr_flags &= ~IFF_PROMISC;
                if(ioctl(socket_fd, SIOCSIFFLAGS, &if_req) == -1) {
                    std::cerr << "Deactivation of promisc mode for " + interface_name << " failed: "
                              << strerror(errno) << std::endl;
                }
            }
        }

        int mtu() {
            ifreq if_req{};
            memset(&if_req, 0, sizeof(if_req));
            memcpy(if_req.ifr_name, interface_name.c_str(), std::min(size_t(sizeof(if_req.ifr_name)),
                                                                     size_t(interface_name.length())));

            if(ioctl(socket_fd, SIOCGIFMTU, &if_req) == -1) {
                throw std::runtime_error((std::string("Getting MTU for ") + interface_name + " failed: "
                                          + strerror(errno)).c_str());
            }

            return if_req.ifr_mtu;
        }

    private:
        std::string interface_name;
    };
}



namespace Test
{
    class CPacket
    {
    public:
        CPacket(size_t pcktSize) : m_pcktSize(pcktSize)
        {
            m_buffer = new char[pcktSize];
        }

        CPacket(size_t pcktSize, char * buffer) : m_pcktSize(pcktSize)
        {
            m_buffer = buffer;
        }

        /// Rule of three (insert to vector uses copy constructor)
        CPacket(const CPacket & second)
        {
            this->m_pcktSize = second.m_pcktSize;
            this->m_buffer   = new char[this->m_pcktSize + 1];
            for (size_t i = 0; i < this->m_pcktSize; i++)
            {
                this->m_buffer[i] = second.m_buffer[i];
            }
            this->m_buffer[this->m_pcktSize] = 0;
        }


        char & operator[](int index) const
        {
            return m_buffer[index];
        }

        friend std::ostream & operator<<(std::ostream & out, const CPacket & pckt)
        {
            size_t size = pckt.getPacketSize();
            for (size_t i = 0; i < size; i++)
            {
                out << pckt[i];
            }
            out << std::endl;
            return out;
        }

        /// Set function(s)
        void setPacketSize(size_t newSize)
        {
            m_pcktSize = newSize;
        }

        /// Get function(s)
        size_t getPacketSize() const
        {
            return m_pcktSize;
        }

        char * getBufferPointer() const
        {
            return m_buffer;
        }

        /// Destructor
        ~CPacket()
        {
            delete [] m_buffer;
        }

    private:
        size_t   m_pcktSize;
        char   * m_buffer;
    };


    std::mutex cout_lock;

    class CTest
    {
    public:
        CTest() = delete;
        CTest(std::string in,
                 std::string out,
                 size_t pcktSize = 128,
                 double duration = 1,
                 size_t vecSize = 10) : m_rcvSckt{in.c_str(), ETH_P_IP}, m_trnsmtSckt{out.c_str(), ETH_P_IP}, m_rx{0}, m_tx{0},
                                     m_pcktSize{pcktSize}, m_duration{duration}, m_vecSize{vecSize}
        {
            std::cout << "LOG: Receving from " << in << ", transmitting to " << out << std::endl;
            std::cout << "LOG: Size of packet is set to " << m_pcktSize << std::endl;
        }

        void
        runTest1()
        {
            using namespace std::chrono;
            high_resolution_clock::time_point start = high_resolution_clock::now();
            duration<double> act_duration;

            do
            {
                this->getPacket();
                this->transmitPacket();
                act_duration = duration_cast<duration<double>>(high_resolution_clock::now() - start);
            } while(act_duration.count() < m_duration);

            std::cout << "LOG: Test 1 (Simple) Received " << m_rx << " bytes; Transmitted " << m_tx << " bytes; in " << act_duration.count() << " seconds" << std::endl;

            m_rx = m_tx = 0;
        }

        void
        runTest2()
        {
            using namespace std::chrono;
            std::cout << "LOG: Size of vector of packets is set to " << m_vecSize << std::endl;
            high_resolution_clock::time_point start = high_resolution_clock::now();
            duration<double> act_duration;
            VecOfPackets pkts(m_vecSize);

            for (auto & it : pkts)
            {
                it.iov_len = m_pcktSize;
                it.iov_base = new char[m_pcktSize];
            }

            do
            {
                for (auto & it : pkts)
                {
                    it.iov_len = m_pcktSize;
                }
                ssize_t c = readv(m_rcvSckt, &pkts[0], m_vecSize);
                
                if (c == -1)
                {
                    throw std::runtime_error("ERROR: Function 'readv' failed");
                }
                else
                {
                    m_rx += c;

                    for (auto & it : pkts)
                    {
                        if (c == 0)
                        {
                            it.iov_len = 0;
                        }
                        else if ((size_t)c <= m_pcktSize)
                        {
                            it.iov_len = c;
                            c = 0;
                        }
                        else
                        {
                            it.iov_len = m_pcktSize;
                            c -= m_pcktSize;
                        }

                        ///std::cout << CPacket{it.iov_len, (char*)it.iov_base}; /// Print packets
                    }

                    c = writev(m_trnsmtSckt, &pkts[0], m_vecSize);
                    if (c == -1)
                    {
                        throw std::runtime_error("ERROR: Function 'writev' failed");
                    }
                    else
                    {
                        m_tx += c;
                    }
                }

                act_duration = duration_cast<duration<double>>(high_resolution_clock::now() - start);
            } while(act_duration.count() < m_duration);

            std::cout << "LOG: Test 2 (Vector of packets) Received " << m_rx << " bytes; Transmitted " << m_tx << " bytes; in " << act_duration.count() << " seconds" << std::endl;

            m_rx = m_tx = 0;
        }

        void
        runTest3()
        {
            m_vctrs.clear();

            std::thread recvThread(&CTest::receivingThread, this, std::bind(&CTest::getPacket, this));
            std::thread tranThread(&CTest::transmittingThread, this, std::bind(&CTest::transmitPacket, this));

            recvThread.join();
            tranThread.join();

            std::cout << "LOG: Test 3 (Multithreaded -- Simple) Received " << m_rx << " bytes; Transmitted " << m_tx << " bytes; in " << m_duration << " seconds" << std::endl;

            m_rx = m_tx = 0;
        }

        void
        runTest4()
        {
            m_pckts.clear();

            std::thread recvThread(&CTest::receivingThread, this, std::bind(&CTest::getVector, this));
            std::thread tranThread(&CTest::transmittingThread, this, std::bind(&CTest::transmitVector, this));

            recvThread.join();
            tranThread.join();

            std::cout << "LOG: Test 4 (Multithreaded -- Vector of packets) Received " << m_rx << " bytes; Transmitted " << m_tx << " bytes; in " << m_duration << " seconds" << std::endl;

            m_rx = m_tx = 0;
        }


    private:

        auto
        g_lock()
        {
            static std::mutex m;
            return std::unique_lock<decltype(m)>(m);
        }

	    void
        receivingThread(std::function<void(void)> && getFunc)
        {
            using namespace std::chrono;
            high_resolution_clock::time_point start = high_resolution_clock::now();
            duration<double> act_duration;

            do
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                {
                    auto lk = g_lock();
                    getFunc();
                }
                act_duration = duration_cast<duration<double>>(high_resolution_clock::now() - start);
            } while(act_duration.count() < m_duration);
	    }

	    void
        transmittingThread(std::function<void(void)> && transmitFunc)
        {
            using namespace std::chrono;
            high_resolution_clock::time_point start = high_resolution_clock::now();
            duration<double> act_duration;

            do
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                {
                    auto lk = g_lock();

                    while(!m_pckts.empty() || !m_vctrs.empty()) // Refactor this cycle
                    {
                        transmitFunc();
                    }
                }
                act_duration = duration_cast<duration<double>>(high_resolution_clock::now() - start);
            } while(act_duration.count() < m_duration);
	    }

        inline void
        transmitVector()
        {
            if (!m_vctrs.empty())
            {
                VecOfPackets pkts = m_vctrs.front();
                ssize_t c;

                c = writev(m_trnsmtSckt, &pkts[0], m_vecSize);
                if (c == -1)
                {
                    throw std::runtime_error("ERROR: Function 'writev' failed");
                }
                else
                {
                    m_tx += c;
                }

                m_vctrs.pop_front();
            }
        }

        inline void
        getVector()
        {
            VecOfPackets pkts(m_vecSize);

            for (auto & it : pkts)
            {
                it.iov_len = m_pcktSize;
                it.iov_base = new char[m_pcktSize];
            }

            ssize_t c = readv(m_rcvSckt, &pkts[0], m_vecSize);
                
            if (c == -1)
            {
                throw std::runtime_error("ERROR: Function 'readv' failed");
            }
            else
            {
                m_rx += c;

                for (auto & it : pkts)
                {
                    if (c == 0)
                    {
                        it.iov_len = 0;
                    }
                    else if ((size_t)c <= m_pcktSize)
                    {
                        it.iov_len = c;
                        c = 0;
                    }
                    else
                    {
                        it.iov_len = m_pcktSize;
                        c -= m_pcktSize;
                    }
                }

                m_vctrs.emplace_back(std::move(pkts));
            }
        }

        inline void
        transmitPacket()
        {
            if (!m_pckts.empty())
            {
                CPacket pckt = m_pckts.front();

                ssize_t transmittedBytes = write(m_trnsmtSckt, pckt.getBufferPointer(), pckt.getPacketSize());

                if (transmittedBytes <= -1)
                {
                    throw std::runtime_error("ERROR: Function 'write' failed");
                }
                else if (transmittedBytes != 0)
                {
                    if ((size_t)transmittedBytes == pckt.getPacketSize())
                    {
                        m_pckts.pop_front();
                    }
                    m_tx += transmittedBytes;
                }
            }
        }

        inline void
        getPacket()
        {
            char * tmpBuffer = new char[m_pcktSize];

            ssize_t readBytes = read(m_rcvSckt, tmpBuffer, m_pcktSize);

            if (readBytes <= -1)
            {
                delete [] tmpBuffer;
                throw std::runtime_error("ERROR: Function 'read' failed");
            }
            else if (readBytes != 0)
            {
                CPacket pckt{(size_t)readBytes, tmpBuffer};
                ///std::cout << pckt; /// Print packet
                m_pckts.push_back(pckt);
                m_rx += readBytes;
            }
            else
            {
                delete [] tmpBuffer;
            }
        }

    public:
        using PacketBuffer = std::deque<CPacket>;
        using VecOfPackets = std::vector<struct iovec>;
        using VectorBuffer = std::deque<VecOfPackets>;

    private:
        /// Receive and transmit sockets
        Sockets::RawSocket    m_rcvSckt;
        Sockets::RawSocket    m_trnsmtSckt;

        /// Packets are stored here
        PacketBuffer m_pckts;

        /// Packet vektors are buffered here
        VectorBuffer m_vctrs;

        /// Rx & Tx bytes counters
        size_t       m_rx;
        size_t       m_tx;

        /// Size of packets (128 by default)
        size_t       m_pcktSize;

        /// Duration of tests
        double       m_duration;

        /// Size of vector of packets (tests 2 & 4)
        size_t       m_vecSize;
    };
}



void help()
{
    std::cout << "Usage: ./main [options]" << std::endl <<
                 "  -i           Number of test [1,2,3,4], 0 to run all, 0 by default" << std::endl <<
                 "  -n           Count of packets transmitted in vector, 10 by default" << std::endl <<
                 "  -p           Size of packet, 128 by default" << std::endl <<
                 "  -r           Receive NI, internet by default" << std::endl <<
                 "  -t           Transmit NI, internet by default" << std::endl <<
                 "  -d           Duration of tests, one sec by default" << std::endl <<
                 "  -h           Prints help" << std::endl;
}


int main(int argc, char ** argv)
{
    int c, vecSize = 10, pcktSize = 128, testNo = 0;
    double duration = 1.0;
    char * recv = (char*)"internet";
    char * tran = (char*)"internet";

    while( ( c = getopt (argc, argv, "i:n:r:t:p:d:h") ) != -1 ) 
    {
        switch(c)
        {
            case 'i':
                if(optarg) testNo = std::atoi(optarg);
                break;

            case 'n':
                if(optarg) vecSize = std::atoi(optarg);
                break;

            case 'p':
                if(optarg) pcktSize = std::atoi(optarg);
                break;

            case 'r':
                if(optarg) recv = optarg;
                break;

            case 't':
                if(optarg) tran = optarg;
                break;

            case 'd':
                if(optarg) duration = std::stod(optarg);
                break;

            case 'h':
                help();
                return 0;
        }
    }

    std::cout << "LOG: Running test number " << testNo << (testNo == 0 ? " (all)" : "") << std::endl;

    try
    {
        Test::CTest test {recv, tran, (size_t)pcktSize, duration, (size_t)vecSize};

        switch(testNo)
        {
            case 0: test.runTest1(); test.runTest2(); test.runTest3(); test.runTest4(); break;
            case 1: test.runTest1(); break;
            case 2: test.runTest2(); break;
            case 3: test.runTest3(); break;
            case 4: test.runTest4(); break;
            default:
            {
                std::cerr << "ERROR: Wrong number of test, choose 0 for all or [1,2,3,4]" << std::endl;
                help();
                return -1;
            }
        }
    }
    catch(std::runtime_error & e)
    {
        std::cerr << e.what() << std::endl;
        return -2;
    }

    return 0;
}
