/////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2022 William C Bonner
//
//	MIT License
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files(the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions :
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.
//
/////////////////////////////////////////////////////////////////////////////
#include <csignal>
#include <cstdio>
#include <cstring> //memset
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <unistd.h> // getopt_long
#include <getopt.h>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
/////////////////////////////////////////////////////////////////////////////
static const std::string ProgramVersionString("DynamicDNSWatcher 1.20221216-1 Built " __DATE__ " at " __TIME__);
int ConsoleVerbosity = 1;
/////////////////////////////////////////////////////////////////////////////
std::string timeToISO8601(const time_t& TheTime)
{
    std::ostringstream ISOTime;
    struct tm UTC;
    if (0 != gmtime_r(&TheTime, &UTC))
    {
        ISOTime.fill('0');
        if (!((UTC.tm_year == 70) && (UTC.tm_mon == 0) && (UTC.tm_mday == 1)))
        {
            ISOTime << UTC.tm_year + 1900 << "-";
            ISOTime.width(2);
            ISOTime << UTC.tm_mon + 1 << "-";
            ISOTime.width(2);
            ISOTime << UTC.tm_mday << "T";
        }
        ISOTime.width(2);
        ISOTime << UTC.tm_hour << ":";
        ISOTime.width(2);
        ISOTime << UTC.tm_min << ":";
        ISOTime.width(2);
        ISOTime << UTC.tm_sec;
    }
    return(ISOTime.str());
}
time_t ISO8601totime(const std::string& ISOTime)
{
    if (ISOTime.length() < 19)
        return(0);
    struct tm UTC;
    UTC.tm_year = stoi(ISOTime.substr(0, 4)) - 1900;
    UTC.tm_mon = stoi(ISOTime.substr(5, 2)) - 1;
    UTC.tm_mday = stoi(ISOTime.substr(8, 2));
    UTC.tm_hour = stoi(ISOTime.substr(11, 2));
    UTC.tm_min = stoi(ISOTime.substr(14, 2));
    UTC.tm_sec = stoi(ISOTime.substr(17, 2));
    UTC.tm_gmtoff = 0;
    UTC.tm_isdst = -1;
    UTC.tm_zone = 0;
#ifdef _MSC_VER
    _tzset();
    _get_daylight(&(UTC.tm_isdst));
#endif
# ifdef __USE_MISC
    time_t timer = timegm(&UTC);
#else
    time_t timer = mktime(&UTC);
    timer -= timezone; // HACK: Works in my initial testing on the raspberry pi, but it's currently not DST
#endif
#ifdef _MSC_VER
    long Timezone_seconds = 0;
    _get_timezone(&Timezone_seconds);
    timer -= Timezone_seconds;
    int DST_hours = 0;
    _get_daylight(&DST_hours);
    long DST_seconds = 0;
    _get_dstbias(&DST_seconds);
    timer += DST_hours * DST_seconds;
#else
#endif
    return(timer);
}
std::string timeToExcelLocal(const time_t& TheTime)
{
    std::ostringstream ExcelDate;
    struct tm UTC;
    if (0 != localtime_r(&TheTime, &UTC))
    {
        ExcelDate.fill('0');
        ExcelDate << UTC.tm_year + 1900 << "-";
        ExcelDate.width(2);
        ExcelDate << UTC.tm_mon + 1 << "-";
        ExcelDate.width(2);
        ExcelDate << UTC.tm_mday << " ";
        ExcelDate.width(2);
        ExcelDate << UTC.tm_hour << ":";
        ExcelDate.width(2);
        ExcelDate << UTC.tm_min << ":";
        ExcelDate.width(2);
        ExcelDate << UTC.tm_sec;
    }
    return(ExcelDate.str());
}
std::string getTimeExcelLocal(void)
{
    time_t timer;
    time(&timer);
    std::string isostring(timeToExcelLocal(timer));
    std::string rval;
    rval.assign(isostring.begin(), isostring.end());
    return(rval);
}
/////////////////////////////////////////////////////////////////////////////
class MyHostAddress {
public:
    MyHostAddress() : SeenFirst(0), SeenLast(0), PingLast(0) {};
    MyHostAddress(const std::string& Address, const time_t& First, const time_t& Last, const time_t Ping = 0)
    {
        address = Address;
        SeenFirst = First;
        SeenLast = Last;
        PingLast = Ping;
    }
    std::string GetAddress() const { return(address); };
    time_t GetFirst() const { return(SeenFirst); };
    time_t GetLast() const { return(SeenLast); };
    time_t GetPing() const { return(PingLast); };
    time_t SetFirst(const time_t Seen) { auto rval = SeenFirst;  SeenFirst = Seen; return(rval); };
    time_t SetLast(const time_t Seen) { auto rval = SeenLast;  SeenLast = Seen; return(rval); };
    time_t SetPing(const time_t Ping) { auto rval = PingLast;  PingLast = Ping; return(rval); };
protected:
    std::string address;
    time_t SeenFirst;
    time_t SeenLast;
    time_t PingLast;
};
void ReadLoggedData(const std::string& filename, std::map<std::string, std::map<std::string, MyHostAddress>>& DNS_Names)
{
    std::ifstream TheFile(filename);
    if (TheFile.is_open())
    {
        std::string TheLine;
        while (std::getline(TheFile, TheLine))
        {
            char buffer[1024];
            if (!TheLine.empty() && (TheLine.size() < sizeof(buffer)))
            {
                // minor garbage check looking for corrupt data with no tab characters
                if (TheLine.find('\t') != std::string::npos)
                {
                    TheLine.copy(buffer, TheLine.size());
                    buffer[TheLine.size()] = '\0';
                    std::string theHost(strtok(buffer, "\t"));
                    std::string theAddress(strtok(NULL, "\t"));
                    std::string the8601First(strtok(NULL, "\t"));
                    std::string the8601Last(strtok(NULL, "\t"));
                    std::string the8601Ping;
                    char* myToken = strtok(NULL, "\t"); if (myToken != NULL) the8601Ping = *myToken;
                    time_t theFirst = ISO8601totime(the8601First);
                    time_t theLast = ISO8601totime(the8601Last);
                    time_t thePing = ISO8601totime(the8601Ping);
                    std::map<std::string, MyHostAddress> TempMap; // empty map to put in map
                    auto Host = DNS_Names.insert(std::pair<std::string, std::map<std::string, MyHostAddress>>(theHost, TempMap));
                    MyHostAddress foo(theAddress, theFirst, theLast, thePing);
                    auto Address = Host.first->second.insert(std::pair <std::string, MyHostAddress>(theAddress, foo));
                    std::cerr << filename << ": " << theHost << " " << theAddress << " " << timeToISO8601(theFirst) << " " << timeToISO8601(theLast) << " " << timeToISO8601(thePing) << std::endl;
                }
            }
        }
        TheFile.close();
    }
}
void WriteLoggedData(const std::string& filename, const std::map<std::string, std::map<std::string, MyHostAddress>> & DNS_Names)
{
    std::ofstream TheFile(filename, std::ios_base::out | std::ios_base::trunc | std::ios_base::ate);
    if (TheFile.is_open())
    {
        for (auto FQDN = DNS_Names.begin(); FQDN != DNS_Names.end(); FQDN++)
        {
            for (auto address = FQDN->second.begin(); address != FQDN->second.end(); address++)
            {
                TheFile << FQDN->first;
                TheFile << "\t" << address->first;
                TheFile << "\t" << timeToISO8601(address->second.GetFirst());
                TheFile << "\t" << timeToISO8601(address->second.GetLast());
                TheFile << "\t" << timeToISO8601(address->second.GetPing());
                TheFile << std::endl;
            }
        }
    }
    TheFile.close();
}
/////////////////////////////////////////////////////////////////////////////
void WriteLoggedDataHTML(const std::string& filename, const std::map<std::string, std::map<std::string, MyHostAddress>>& DNS_Names)
{
    std::ofstream TheFile(filename, std::ios_base::out | std::ios_base::trunc | std::ios_base::ate);
    if (TheFile.is_open())
    {
        TheFile << "<!DOCTYPE html>" << std::endl;
        TheFile << "<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\">" << std::endl;
        TheFile << "<head>" << std::endl;
        TheFile << "\t<meta charset=\"utf-8\" />" << std::endl;
        TheFile << "\t<title>" << ProgramVersionString << "</title>" << std::endl;
        TheFile << "</head>" << std::endl;
        TheFile << "<body>" << std::endl;
        time_t timer;
        time(&timer);
        TheFile << "<p>Current Time: " << timeToISO8601(timer) << "</p>" << std::endl;
        TheFile << "<table id=\"MyTable\">" << std::endl;
        TheFile << "\t<tr>";
        TheFile << "<th onclick=\"sortTable(0)\">Hostname</th>";
        TheFile << "<th onclick=\"sortTable(1)\">Last Seen</th>";
        TheFile << "<th onclick=\"sortTable(2)\">First Seen</th>";
        TheFile << "<th onclick=\"sortTable(3)\">Address</th>";
        TheFile << "<th onclick=\"sortTable(4)\">Last Ping</th>";
        TheFile << "</tr>" << std::endl;
        for (auto FQDN = DNS_Names.begin(); FQDN != DNS_Names.end(); FQDN++)
        {
            for (auto address = FQDN->second.begin(); address != FQDN->second.end(); address++)
            {
                TheFile << "\t<tr>";
                TheFile << "<td>" << FQDN->first << "</td>";
                TheFile << "<td>" << timeToISO8601(address->second.GetLast()) << "</td>";
                TheFile << "<td>" << timeToISO8601(address->second.GetFirst()) << "</td>";
                TheFile << "<td>" << address->first << "</td>";
                TheFile << "<td>" << timeToISO8601(address->second.GetPing()) << "</td>";
                TheFile << "</tr>" << std::endl;
            }
        }
        TheFile << "</table>" << std::endl;

        TheFile << "<script>" << std::endl;
        TheFile << "function sortTable(n) {" << std::endl;
        TheFile << "\tvar table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;" << std::endl;
        TheFile << "\ttable = document.getElementById(\"MyTable\");" << std::endl;
        TheFile << "\tswitching = true;" << std::endl;
        TheFile << "\tdir = \"asc\";" << std::endl;
        TheFile << "\twhile (switching) {" << std::endl;
        TheFile << "\t\tswitching = false;" << std::endl;
        TheFile << "\t\trows = table.rows;" << std::endl;
        TheFile << "\t\tfor (i = 1; i < (rows.length - 1); i++) {" << std::endl;
        TheFile << "\t\t\tshouldSwitch = false;" << std::endl;
        TheFile << "\t\t\tx = rows[i].getElementsByTagName(\"TD\")[n];" << std::endl;
        TheFile << "\t\t\ty = rows[i + 1].getElementsByTagName(\"TD\")[n];" << std::endl;
        TheFile << "\t\t\tif (dir == \"asc\") {" << std::endl;
        TheFile << "\t\t\t\tif (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {" << std::endl;
        TheFile << "\t\t\t\t\tshouldSwitch= true;" << std::endl;
        TheFile << "\t\t\t\t\tbreak;" << std::endl;
        TheFile << "\t\t\t\t}" << std::endl;
        TheFile << "\t\t\t} else if (dir == \"desc\") {" << std::endl;
        TheFile << "\t\t\t\tif (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {" << std::endl;
        TheFile << "\t\t\t\t\tshouldSwitch = true;" << std::endl;
        TheFile << "\t\t\t\t\tbreak;" << std::endl;
        TheFile << "\t\t\t\t}" << std::endl;
        TheFile << "\t\t\t}" << std::endl;
        TheFile << "\t\t}" << std::endl;
        TheFile << "\t\tif (shouldSwitch) {" << std::endl;
        TheFile << "\t\t\trows[i].parentNode.insertBefore(rows[i + 1], rows[i]);" << std::endl;
        TheFile << "\t\t\tswitching = true;" << std::endl;
        TheFile << "\t\t\tswitchcount ++;" << std::endl;
        TheFile << "\t\t} else {" << std::endl;
        TheFile << "\t\t\tif (switchcount == 0 && dir == \"asc\") {" << std::endl;
        TheFile << "\t\t\t\tdir = \"desc\";" << std::endl;
        TheFile << "\t\t\t\tswitching = true;" << std::endl;
        TheFile << "\t\t\t}" << std::endl;
        TheFile << "\t\t}" << std::endl;
        TheFile << "\t}" << std::endl;
        TheFile << "}" << std::endl;
        TheFile << "</script>" << std::endl;

        TheFile << "</body>" << std::endl;
        TheFile << "</html>" << std::endl;
    }
    TheFile.close();
}
/////////////////////////////////////////////////////////////////////////////
std::vector<std::string> dns_lookup(const std::string& host_name)
{
    std::vector<std::string> output;
    int status;
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res;
    if ((status = getaddrinfo(host_name.c_str(), NULL, &hints, &res)) != 0) 
    {
        std::cerr << "getaddrinfo: "<< gai_strerror(status) << " (" << host_name << ")" << std::endl;
        return(output);
    }
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) 
    {
        void* addr;
        if (p->ai_family == AF_INET) 
        { // IPv4
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
        }
        else 
        { // IPv6
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        // convert the IP to a string
        char ip_address[INET6_ADDRSTRLEN];
        inet_ntop(p->ai_family, addr, ip_address, sizeof(ip_address));
        output.push_back(ip_address);
    }
    freeaddrinfo(res); // free the linked list
    return(output);
}
/////////////////////////////////////////////////////////////////////////////

// https://www.geeksforgeeks.org/ping-in-c/
// http://tcpipguide.com/free/t_ICMPv6EchoRequestandEchoReplyMessages-2.htm
// https://cboard.cprogramming.com/c-programming/38408-ipv6-ping-windows-problem-lots-ode.html
// https://www.tutorialspoint.com/unix_sockets/ip_address_functions.htm
// https://en.wikipedia.org/wiki/ICMPv6
// https://github.com/octo/liboping/blob/master/src/liboping.c
// https://pall.as/icmpv6-and-ipv6-neighborships/
// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64
#define PING_SLEEP_RATE 1000000

// Gives the timeout delay for receiving packets in seconds
#define RECV_TIMEOUT 1

// ping packet structure
struct ping_pkt
{
    struct icmphdr hdr;
    char msg[PING_PKT_S - sizeof(struct icmphdr)];
};

// Calculating the Check Sum
unsigned short checksum(void* b, int len)
{
    unsigned short* buf = (unsigned short*) b;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    unsigned short result = ~sum;
    return result;
}

bool send_ping4(const std::string& ping_ip, const std::string& HostName4Output, const bool bOutput = false)
{
    bool rval = false;
    if (bOutput)
        std::cout << "[" << getTimeExcelLocal() << "] " << "send_ping4(" << ping_ip << ", " << HostName4Output << ");" << std::endl;
    struct timespec tfs;
    clock_gettime(CLOCK_MONOTONIC, &tfs);
    auto ping_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ping_sockfd < 0)
    {
        if (bOutput)
            std::cout << "[" << getTimeExcelLocal() << "] " << "Socket file descriptor not received!!" << std::endl;
    }
    else
    {
        // set socket options at ip to TTL and value to 64,
        // change to what you want by setting ttl_val
        int ttl_val = 64;
        if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
        {
            if (bOutput)
                std::cout << "[" << getTimeExcelLocal() << "] " << "Setting socket options to TTL failed!" << std::endl;
        }
        else
        {
            const int one = 1;
            /* Enable receiving the TOS field */
            setsockopt(ping_sockfd, IPPROTO_IP, IP_RECVTOS, &one, sizeof(one));
            /* Enable receiving the TTL field */
            setsockopt(ping_sockfd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));

            // setting timeout of recv setting
            struct timeval tv_out;
            tv_out.tv_sec = RECV_TIMEOUT;
            tv_out.tv_usec = 0;
            setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

            int msg_count = 0;
            int flag = 1;
            int msg_received_count = 0;
            // send icmp packet in a loop
            for (auto pingloop = 4; pingloop > 0; pingloop--)
            {
                // flag is whether packet was sent or not
                flag = 1;

                //filling packet
                struct ping_pkt pckt;
                bzero(&pckt, sizeof(pckt));
                for (auto i = 0; i < sizeof(pckt.msg) - 1; i++)
                    pckt.msg[i] = i + '0';
                pckt.msg[sizeof(pckt.msg) - 1] = 0;
                pckt.hdr.type = ICMP_ECHO;
                pckt.hdr.un.echo.id = getpid();
                pckt.hdr.un.echo.sequence = msg_count++;
                pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

                usleep(PING_SLEEP_RATE);

                struct timespec time_start;
                clock_gettime(CLOCK_MONOTONIC, &time_start);

                struct sockaddr_in ping_addr;
                ping_addr.sin_family = AF_INET;
                ping_addr.sin_port = htons(0);
                //ping_addr.sin_addr.s_addr = inet_addr(ping_ip.c_str());
                inet_pton(AF_INET, ping_ip.c_str(), &ping_addr.sin_addr.s_addr);

                if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&ping_addr, sizeof(ping_addr)) <= 0)
                {
                    if (bOutput)
                        std::cout << "[" << getTimeExcelLocal() << "] " << "Packet Sending Failed!" << std::endl;
                    flag = 0;
                }
                //receive packet
                struct sockaddr_in r_addr;
                auto addr_len = sizeof(r_addr);
                if (recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, (socklen_t*)&addr_len) <= 0 && msg_count > 1)
                {
                    if (bOutput)
                        std::cout << "[" << getTimeExcelLocal() << "] " << "Packet receive failed!" << std::endl;
                }
                else
                {
                    struct timespec time_end;
                    clock_gettime(CLOCK_MONOTONIC, &time_end);

                    double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
                    long double rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

                    // if packet was not sent, don't receive
                    if (flag)
                    {
                        if (!(pckt.hdr.type == 69 && pckt.hdr.code == 0))
                        {
                            if (bOutput)
                                std::cerr << "[" << getTimeExcelLocal() << "] " << "Error..Packet received with ICMP type " << int(pckt.hdr.type) << " code " << int(pckt.hdr.code) << std::endl;
                        }
                        else
                        {
                            char szAddr[NI_MAXHOST] = { 0 };
                            inet_ntop(AF_INET, &r_addr.sin_addr, szAddr, sizeof(szAddr));
                            if (bOutput)
                                std::cout << "[" << getTimeExcelLocal() << "] " << PING_PKT_S << " bytes from (" << szAddr << ") (" << HostName4Output << ") msg_seq=" << msg_count << " ttl=" << ttl_val << " rtt= " << rtt_msec << " ms." << std::endl;
                            msg_received_count++;
                        }
                    }
                }
            }
            rval = msg_received_count > 0;
            struct timespec tfe;
            clock_gettime(CLOCK_MONOTONIC, &tfe);
            double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
            long double total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;
            if (bOutput)
                std::cout << "[" << getTimeExcelLocal() << "] " << "=== " << ping_ip << " ping statistics === " << msg_count << " packets sent, " << msg_received_count << " packets received, " << ((msg_count - msg_received_count) / msg_count) * 100.0 << " percent packet loss. Total time : " << total_msec << " ms." << std::endl;
        }
        close(ping_sockfd);
    }
    return(rval);
}

bool send_ping6(const std::string& ping_ip, const std::string& HostName4Output, const bool bOutput = false)
{
    bool rval = false;
    if (bOutput)
        std::cout << "[" << getTimeExcelLocal() << "] " << "send_ping6(" << ping_ip << ", " << HostName4Output << ");" << std::endl;
    struct timespec tfs;
    clock_gettime(CLOCK_MONOTONIC, &tfs);
    auto ping_sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (ping_sockfd < 0)
    {
        if (bOutput)
            std::cout << "[" << getTimeExcelLocal() << "] " << "Socket file descriptor not received!!" << std::endl;
    }
    else
    {
        // set socket options at ip to TTL and value to 64,
        // change to what you want by setting ttl_val
        int ttl_val = 64;
        if (setsockopt(ping_sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl_val, sizeof(ttl_val)) != 0)
        {
            if (bOutput)
                std::cerr << "[" << getTimeExcelLocal() << "] " << "Setting socket options to TTL failed!" << std::endl;
        }
        else
        {
            //const int one = 1;
            /* For details see RFC 3542, section 6.3. */
            //setsockopt(ping_sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
            /* For details see RFC 3542, section 6.5. */
            //setsockopt(ping_sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof(one));

            // the filtering is copied from: https://git.busybox.net/busybox/tree/networking/ping.c
            struct icmp6_filter filt;
            ICMP6_FILTER_SETBLOCKALL(&filt);
            ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
            setsockopt(ping_sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));

            // setting timeout of recv setting
            struct timeval tv_out;
            tv_out.tv_sec = RECV_TIMEOUT;
            tv_out.tv_usec = 0;
            setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

            int msg_count = 0;
            int flag = 1;
            int msg_received_count = 0;
            // send icmp packet in a loop
            for (auto pingloop = 4; pingloop > 0; pingloop--)
            {
                // flag is whether packet was sent or not
                flag = 1;

                //filling packet
                struct ping_pkt pckt;
                bzero(&pckt, sizeof(pckt));
                for (auto i = 0; i < sizeof(pckt.msg) - 1; i++)
                    pckt.msg[i] = i + '0';
                pckt.msg[sizeof(pckt.msg) - 1] = 0;
                pckt.hdr.type = ICMP6_ECHO_REQUEST;
                pckt.hdr.un.echo.id = getpid();
                pckt.hdr.un.echo.sequence = msg_count++;
                pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

                usleep(PING_SLEEP_RATE);

                struct timespec time_start;
                clock_gettime(CLOCK_MONOTONIC, &time_start);

                struct sockaddr_in6 ping_addr;
                ping_addr.sin6_family = AF_INET6;
                ping_addr.sin6_port = htons(0);
                inet_pton(AF_INET6, ping_ip.c_str(), &ping_addr.sin6_addr);
                if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&ping_addr, sizeof(ping_addr)) <= 0)
                {
                    if (bOutput)
                        std::cout << "[" << getTimeExcelLocal() << "] " << "Packet Sending Failed!" << std::endl;
                    flag = 0;
                }

                //receive packet
                struct sockaddr_in6 r_addr;
                auto addr_len = sizeof(r_addr);
                if (recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, (socklen_t*)&addr_len) <= 0 && msg_count > 1)
                {
                    if (bOutput)
                        std::cout << "[" << getTimeExcelLocal() << "] " << "Packet receive failed!" << std::endl;
                }
                else
                {
                    struct timespec time_end;
                    clock_gettime(CLOCK_MONOTONIC, &time_end);

                    double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
                    long double rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

                    // if packet was not sent, don't receive
                    if (flag)
                    {
                        char szAddr[NI_MAXHOST] = { 0 };
                        inet_ntop(AF_INET6, &r_addr.sin6_addr, szAddr, sizeof(szAddr));
                        if (!(pckt.hdr.type == ICMP6_ECHO_REPLY && pckt.hdr.code == 0))
                        {
                            if (bOutput)
                                std::cout << "[" << getTimeExcelLocal() << "] " << "Error..Packet received from (" << szAddr << ") with ICMP type " << int(pckt.hdr.type) << " code " << int(pckt.hdr.code) << std::endl;
                        }
                        else
                        {
                            if (bOutput)
                                std::cout << "[" << getTimeExcelLocal() << "] " << PING_PKT_S << " bytes from (" << szAddr << ") (" << HostName4Output << ") msg_seq=" << msg_count << " ttl=" << "ttl_val" << " rtt= " << rtt_msec << " ms." << std::endl;
                            msg_received_count++;
                        }
                    }
                }
            }
            rval = msg_received_count > 0;
            struct timespec tfe;
            clock_gettime(CLOCK_MONOTONIC, &tfe);
            double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
            long double total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;
            if (bOutput)
                std::cout << "[" << getTimeExcelLocal() << "] " << "=== " << ping_ip << " ping statistics === " << msg_count << " packets sent, " << msg_received_count << " packets received, " << ((msg_count - msg_received_count) / msg_count) * 100.0 << " percent packet loss. Total time : " << total_msec << " ms." << std::endl;
        }
        close(ping_sockfd);
    }
    return(rval);
}
// make a ping request
bool send_ping(const std::string& ping_ip, const std::string& HostName4Output, const bool bOutput = false)
{
    bool rval = false;
    if (ping_ip.find('.') == std::string::npos)
        rval = send_ping6(ping_ip, HostName4Output, bOutput);
    else 
        rval = send_ping4(ping_ip, HostName4Output, bOutput);
    return(rval);
}
/////////////////////////////////////////////////////////////////////////////
volatile bool bRun = true; // This is declared volatile so that the compiler won't optimized it out of loops later in the code
void SignalHandlerSIGINT(int signal)
{
    bRun = false;
    std::cerr << "***************** SIGINT: Caught Ctrl-C, finishing loop and quitting. *****************" << std::endl;
}
volatile bool bFlush = false;
void SignalHandlerSIGHUP(int signal)
{
    bFlush = true;
    std::cerr << "***************** SIGHUP: Caught HangUp, finishing loop and flushing log. *****************" << std::endl;
}
void SignalHandlerSIGALRM(int signal)
{
    bFlush = true;
}
/////////////////////////////////////////////////////////////////////////////
static void usage(int argc, char** argv)
{
    std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
    std::cout << "  " << ProgramVersionString << std::endl;
    std::cout << "  Options:" << std::endl;
    std::cout << "    -h | --help          Print this message" << std::endl;
    std::cout << "    -v | --verbose level stdout verbosity level [" << ConsoleVerbosity << "]" << std::endl;
    std::cout << "    -n | --name fqdn     Fully Qualified Domain Name to watch" << std::endl;
    std::cout << "    -f | --file path     Fully Qualified Path Name to store data" << std::endl;
    std::cout << "    -o | --output path   Fully Qualified Path Name to store html output" << std::endl;
    std::cout << "    -m | --minutes 5     number of minutes between updating output files" << std::endl;
    std::cout << std::endl;
}
static const char short_options[] = "hv:n:f:o:m:";
static const struct option long_options[] = {
    { "help",no_argument,           NULL, 'h' },
    { "verbose",required_argument,  NULL, 'v' },
    { "name",required_argument,     NULL, 'n' },
    { "file",required_argument,     NULL, 'f' },
    { "output",required_argument,   NULL, 'o' },
    { "minutes",required_argument,  NULL, 'm' },
    { 0, 0, 0, 0 }
};
/////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
    ///////////////////////////////////////////////////////////////////////////////////////////////
    tzset();
    ///////////////////////////////////////////////////////////////////////////////////////////////
    std::map<std::string, std::map<std::string, MyHostAddress>> DNS_Names_ToWatch;    // memory map of Hostnames and their addresses
    std::string CacheFileName;
    std::string OutputFileName;
    int MinutesBetweenFileWrites = 5;
    ///////////////////////////////////////////////////////////////////////////////////////////////
    for (;;)
    {
        std::string TempString;
        std::map<std::string, MyHostAddress> TempMap; // empty map to put in map
        int idx;
        int c = getopt_long(argc, argv, short_options, long_options, &idx);
        if (-1 == c)
            break;
        switch (c)
        {
        case 0: /* getopt_long() flag */
            break;
        case 'h':
            usage(argc, argv);
            exit(EXIT_SUCCESS);
        case 'v':
            try { ConsoleVerbosity = std::stoi(optarg); }
            catch (const std::invalid_argument& ia) { std::cerr << "Invalid argument: " << ia.what() << std::endl; exit(EXIT_FAILURE); }
            catch (const std::out_of_range& oor) { std::cerr << "Out of Range error: " << oor.what() << std::endl; exit(EXIT_FAILURE); }
            break;
        case 'n':
            DNS_Names_ToWatch.insert(std::pair<std::string, std::map<std::string, MyHostAddress>>(std::string(optarg), TempMap));
            break;
        case 'f':
            CacheFileName = std::string(optarg);
            break;
        case 'o':
            OutputFileName = std::string(optarg);
            break;
        case 'm':
            try { MinutesBetweenFileWrites = std::stoi(optarg); }
            catch (const std::invalid_argument& ia) { std::cerr << "Invalid argument: " << ia.what() << std::endl; exit(EXIT_FAILURE); }
            catch (const std::out_of_range& oor) { std::cerr << "Out of Range error: " << oor.what() << std::endl; exit(EXIT_FAILURE); }
            break;
        default:
            usage(argc, argv);
            exit(EXIT_FAILURE);
        }
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////
    // I don't print the banner earlier because I haven't interpreted ConsoleVerbosity until I've parsed the parameters!
    if (ConsoleVerbosity > 0)
    {
        std::cout << "[" << getTimeExcelLocal() << "] " << ProgramVersionString << std::endl;
        std::ostringstream startupargs;
        for (auto index = 0; index < argc; index++)
            startupargs << " " << argv[index];
        std::cout << "[" << getTimeExcelLocal() << "] " << startupargs.str() << std::endl;
    }
    else
    {
        std::ostringstream startupargs;
        startupargs << ProgramVersionString << " (starting)" << std::endl;
        for (auto index = 0; index < argc; index++)
            startupargs << " " << argv[index];
        std::cerr << startupargs.str() << std::endl;
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////
    // Set up CTR-C signal handler
    auto previousHandler = signal(SIGINT, SignalHandlerSIGINT);
    auto previousHUPHandler = signal(SIGHUP, SignalHandlerSIGHUP);
    auto previousAlarmHandler = signal(SIGALRM, SignalHandlerSIGALRM);
    alarm(MinutesBetweenFileWrites * 60);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    ReadLoggedData(CacheFileName, DNS_Names_ToWatch);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    bRun = true;
    while (bRun)
    {
        //time_t LoopStartTime;
        //time(&LoopStartTime);
        for (auto FQDN = DNS_Names_ToWatch.begin(); FQDN != DNS_Names_ToWatch.end(); FQDN++)
        {
            if (ConsoleVerbosity > 0)
                std::cout << "[" << getTimeExcelLocal() << "] " << FQDN->first;
            time_t t_now;
            time(&t_now);
            std::vector<std::string> addresses = dns_lookup(FQDN->first);
            for (auto address = addresses.begin(); address != addresses.end(); address++)
            {
                if (ConsoleVerbosity > 0)
                    std::cout << " " << *address;
                MyHostAddress foo(*address, t_now, t_now);
                auto Address = FQDN->second.insert(std::pair <std::string, MyHostAddress>(*address, foo));
                if (Address.second == false)    // Address Already was in map
                    Address.first->second.SetLast(t_now);
                else
                    std::cerr << FQDN->first << " " << *address << std::endl;
                if (send_ping(*address, FQDN->first, (ConsoleVerbosity > 0)))
                {
                    Address.first->second.SetPing(t_now);
                    if (ConsoleVerbosity > 0)
                        std::cout << " Ping=True";
                }
            }
            if (ConsoleVerbosity > 0)
                std::cout << std::endl;
        }
        sleep(1 * 60);
        if (bFlush)
        {
            WriteLoggedData(CacheFileName, DNS_Names_ToWatch);
            if (!OutputFileName.empty())
                WriteLoggedDataHTML(OutputFileName, DNS_Names_ToWatch);
            bFlush = false;
            alarm(MinutesBetweenFileWrites * 60);
        }
    }
    WriteLoggedData(CacheFileName, DNS_Names_ToWatch);
    if (!OutputFileName.empty())
        WriteLoggedDataHTML(OutputFileName, DNS_Names_ToWatch);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    signal(SIGALRM, previousAlarmHandler);
    signal(SIGHUP, previousHUPHandler);
    // remove our special Ctrl-C signal handler and restore previous one
    signal(SIGINT, previousHandler);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    std::cerr << ProgramVersionString << " (exiting)" << std::endl;
    return(EXIT_SUCCESS);
}
