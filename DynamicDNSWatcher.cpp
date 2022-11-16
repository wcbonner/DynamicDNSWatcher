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
static const std::string ProgramVersionString("DynamicDNSWatcher 1.20221116-1 Built " __DATE__ " at " __TIME__);
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
    MyHostAddress() : SeenFirst(0), SeenLast(0) {};
    MyHostAddress(const std::string& Address, const time_t& First, const time_t& Last)
    {
        address = Address;
        SeenFirst = First;
        SeenLast = Last;
    }
    std::string GetAddress() const { return(address); };
    time_t GetFirst() const { return(SeenFirst); };
    time_t GetLast() const { return(SeenLast); };
    time_t SetFirst(const time_t Seen) { auto rval = SeenFirst;  SeenFirst = Seen; return(rval); };
    time_t SetLast(const time_t Seen) { auto rval = SeenLast;  SeenLast = Seen; return(rval); };
protected:
    std::string address;
    time_t SeenFirst;
    time_t SeenLast;
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
                    time_t theFirst = ISO8601totime(the8601First);
                    time_t theLast = ISO8601totime(the8601Last);
                    std::map<std::string, MyHostAddress> TempMap; // empty map to put in map
                    auto Host = DNS_Names.insert(std::pair<std::string, std::map<std::string, MyHostAddress>>(theHost, TempMap));
                    MyHostAddress foo(theAddress, theFirst, theLast);
                    auto Address = Host.first->second.insert(std::pair <std::string, MyHostAddress>(theAddress, foo));
                    std::cerr << filename << ": " << theHost << " " << theAddress << " " << timeToISO8601(theFirst) << " " << timeToISO8601(theLast) << std::endl;
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
        TheFile << "<th onclick=\"sortTable(1)\">Address</th>";
        TheFile << "<th onclick=\"sortTable(2)\">First Seen</th>";
        TheFile << "<th onclick=\"sortTable(3)\">Last Seen</th>";
        TheFile << "</tr>" << std::endl;
        for (auto FQDN = DNS_Names.begin(); FQDN != DNS_Names.end(); FQDN++)
        {
            for (auto address = FQDN->second.begin(); address != FQDN->second.end(); address++)
            {
                TheFile << "\t<tr>";
                TheFile << "<td>" << FQDN->first << "</td>";
                TheFile << "<td>" << address->first << "</td>";
                TheFile << "<td>" << timeToISO8601(address->second.GetFirst()) << "</td>";
                TheFile << "<td>" << timeToISO8601(address->second.GetLast()) << "</td>";
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
    std::cout << std::endl;
}
static const char short_options[] = "hv:n:f:o:";
static const struct option long_options[] = {
    { "help",no_argument,           NULL, 'h' },
    { "verbose",required_argument,  NULL, 'v' },
    { "name",required_argument,     NULL, 'n' },
    { "file",required_argument,     NULL, 'f' },
    { "output",required_argument,   NULL, 'o' },
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
    alarm(60 * 60); // one hour
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
            alarm(60 * 60); // one hour
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
