#include <csignal>
#include <cstdio>
#include <cstring> //memset
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h> // getopt_long
#include <getopt.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
/////////////////////////////////////////////////////////////////////////////
static const std::string ProgramVersionString("DynamicDNSWatcher 1.20220802-1 Built " __DATE__ " at " __TIME__);
int ConsoleVerbosity = 1;
/////////////////////////////////////////////////////////////////////////////
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
        std::cerr << "getaddrinfo: "<< gai_strerror(status) << std::endl;
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
void SignalHandlerSIGHUP(int signal)
{
    bRun = false;
    std::cerr << "***************** SIGHUP: Caught HangUp, finishing loop and quitting. *****************" << std::endl;
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
    std::cout << std::endl;
}
static const char short_options[] = "hv:n:";
static const struct option long_options[] = {
    { "help",no_argument,			NULL, 'h' },
    { "verbose",required_argument,	NULL, 'v' },
    { "name",required_argument,     NULL, 'n' },
    { 0, 0, 0, 0 }
};
/////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
    ///////////////////////////////////////////////////////////////////////////////////////////////
    tzset();
    ///////////////////////////////////////////////////////////////////////////////////////////////
    std::vector<std::string> DNS_Names_ToWatch;
    ///////////////////////////////////////////////////////////////////////////////////////////////
    for (;;)
    {
        std::string TempString;
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
            DNS_Names_ToWatch.push_back(std::string(optarg));
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
    typedef void (*SignalHandlerPointer)(int);
    SignalHandlerPointer previousHandler = signal(SIGINT, SignalHandlerSIGINT);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    bRun = true;
    while (bRun)
    {
        time_t LoopStartTime;
        time(&LoopStartTime);
        for (auto FQDN = DNS_Names_ToWatch.begin(); FQDN != DNS_Names_ToWatch.end(); FQDN++)

        {
            std::cout << "[" << getTimeExcelLocal() << "] " << *FQDN;
            std::vector<std::string> addresses = dns_lookup(*FQDN);
            for (auto iter = addresses.begin(); iter != addresses.end(); iter++)
                std::cout << " " << *iter;
            std::cout << std::endl;
        }
        sleep(1 * 60);
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////
    // remove our special Ctrl-C signal handler and restore previous one
    signal(SIGINT, previousHandler);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    std::cerr << ProgramVersionString << " (exiting)" << std::endl;
    return(EXIT_SUCCESS);
}