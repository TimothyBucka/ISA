// Made by: Timotej Bucka (xbucka00)

#ifndef DHCP_STATS_HPP
#define DHCP_STATS_HPP

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <ncurses.h>
#include <pcap.h>
#include <string.h>
#include <syslog.h>
#include <unordered_set>
#include <vector>

using namespace std;

#define IP4_ADDR_LEN 32

enum ErrCodes {
    SUCCESS = 0,
    INVALID_PROGRAM_ARGS = 1,
    INVALID_PREFIX,
    PCAP_OPEN,
    PCAP_COMPILE,
    PCAP_SETFILTER
};

class IPPrefix {
private:
    string address;
    uint32_t bitAddress;
    uint32_t broadcastBitAddress;
    int maskNumber;
    uint32_t bitMask;
    int allocated;
    int used;
    float usage;
    bool logged;

public:
    IPPrefix();
    IPPrefix(string prefix);

    void addUsed(int = 1);
    void setLogged(bool = true);

    string getAddress();
    uint32_t getBitAddress();
    uint32_t getBroadcastBitAddress();
    int getMaskNumber();
    uint32_t getBitMask();
    int getAllocated();
    int getUsed();
    float getUsage();
    bool getLogged();
};

struct ProgramArguments {
    string fileName;
    string interface;
    vector<IPPrefix> prefixes;
};

/**
 * Signal handler for SIGINT. Closes pcap descriptor, ends curses mode, closes syslog. Exits with SUCCESS.
 *
 * @param s int - Signal number. Not used.
 */
void sigint_handler(int s);

/**
 * Closes pcap descriptor, closes syslog, ends curses mode.
*/
void cleanup();

/**
 * Parses program arguments. Exits with INVALID_PROGRAM_ARGS if invalid arguments were specified.
 *
 * @param argc int - Number of arguments.
 * @param argv char** - Array of arguments.
 * @return ProgramArguments - Parsed arguments.
 */
ProgramArguments parseArguments(int argc, char *argv[]);

/**
 * Callback function for pcap_loop. Processes packets, updates and prints stats, logs to syslog.
 *
 * @param args u_char* - Are not used
 * @param pkthdr const struct pcap_pkthdr* - Packet header. Not used.
 * @param packet const u_char* - Packet data.
 */
void packetCallback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

/**
 * Prints stats to standard output. Used when reading packets from file.
 */
void printAllStatsStd();

/**
 * Prints prefix stats to standard output
 *
 * @param prefix IPPrefix - prefix to print

*/
void printPrefixStatsStd(IPPrefix prefix);

/**
 * Prints stats to ncurses window. Used when reading packets from interface.
 */
void printAllStatsNcurses();

/**
 * Prints prefix stats to ncurses window
 *
 * @param prefix IPPrefix - prefix to print
 */
void printPrefixStatsNcurses(IPPrefix prefix);

// global variables
extern unordered_set<uint32_t> readAddresses;
extern ProgramArguments g_args;
extern pcap_t *descr; // to be able to close it in signal handler
extern struct bpf_program fp; // to be able to free it in signal handler

#endif