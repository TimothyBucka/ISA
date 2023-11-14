// Made by: Timotej Bucka (xbucka00)

#include "dhcp-stats.hpp"

ProgramArguments g_args;
unordered_set<uint32_t> readAddresses = {};
pcap_t *descr;
struct bpf_program fp;

void sigint_handler(int s) {
    (void)s;

    cleanup();

    cout << "SIGINT received, exiting" << endl;

    exit(SUCCESS);
}

void cleanup() {
    if (descr != NULL)
        pcap_close(descr);

    if (fp.bf_len > 0)
        pcap_freecode(&fp);

    closelog();

    if (!g_args.interface.empty())
        endwin(); // end curses mode
}

ProgramArguments parseArguments(int argc, char *argv[]) {
    ProgramArguments args;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            cout << "Usage: " << argv[0] << " [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]" << endl;
            exit(SUCCESS);
        } else if (!strcmp(argv[i], "-r")) {
            if (i + 1 >= argc) {
                cerr << "No file specified" << endl;
                exit(INVALID_PROGRAM_ARGS);
            }
            args.fileName = argv[++i];
        } else if (!strcmp(argv[i], "-i")) {
            if (i + 1 >= argc) {
                cerr << "No interface specified" << endl;
                exit(INVALID_PROGRAM_ARGS);
            }
            args.interface = argv[++i];
        } else {
            try {
                args.prefixes.push_back(IPPrefix(argv[i]));
            } catch (ErrCodes e) {
                cerr << "Invalid prefix" << endl;
                exit(INVALID_PREFIX);
            }
        }
    }

    // if no prefixes were specified
    if (args.prefixes.size() == 0) {
        cerr << "No prefixes specified" << endl;
        exit(INVALID_PROGRAM_ARGS);
    }

    // if neither of -i or -r was specified
    if (args.fileName.empty() && args.interface.empty()) {
        cerr << "No file or interface specified" << endl;
        exit(INVALID_PROGRAM_ARGS);
    }

    // if both -i and -r were specified
    if (!args.fileName.empty() && !args.interface.empty()) {
        cerr << "Both file and interface specified" << endl;
        exit(INVALID_PROGRAM_ARGS);
    }

    return args;
}

void packetCallback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)args;
    (void)pkthdr;

    // remove ethernet ip and udp header
    packet += 14 + 20 + 8;

    // get to yiaddr
    const uint8_t *yiaddr_ptr = packet + 16;
    uint32_t ip = 0;
    memcpy(&ip, yiaddr_ptr, 4);
    ip = ntohl(ip);

    // get to options
    bool is_ack = false;
    const uint8_t *option_ptr = packet + 240; // see rfc2131

    while (*option_ptr != 255) {
        const uint8_t *option_len_ptr = option_ptr + 1;
        if (*option_len_ptr == 0) {
            option_ptr += 2;
            continue;
        }

        const uint8_t *option_data_ptr = option_ptr + 2;

        if (*option_ptr == 53 && *option_data_ptr == 5) {
            is_ack = true;
            break;
        }

        option_ptr += *option_len_ptr + 2; // +2 to skip option_length bit and start after option_data bits
    }

    if (!is_ack) {
        return;
    }

    // if ip was already processed
    if (readAddresses.find(ip) != readAddresses.end()) {
        return;
    }
    readAddresses.insert(ip);

    int row = 0;
    for (auto &prefix : g_args.prefixes) {
        row++;
        if ((ip & prefix.getBitMask()) == (prefix.getBitAddress() & prefix.getBitMask()) && ip != prefix.getBitAddress() && ip != prefix.getBroadcastBitAddress()) {
            prefix.addUsed();

            if (prefix.getUsage() > 0.5 && !prefix.getLogged()) {
                // log to dhcp-stats
                syslog(LOG_NOTICE, "prefix %s/%d exceeded 50%% of allocations .", prefix.getAddress().c_str(), prefix.getMaskNumber());
                prefix.setLogged();
            }

            if (!g_args.interface.empty()) {
                move(row, 0);
                printPrefixStatsNcurses(prefix);
                refresh();
            }
        }
    }
}

void printAllStatsStd() {
    cout << "IP-Prefix\tMax-hosts\tAllocated\tUtilization\tOver50%" << endl;
    for (auto &prefix : g_args.prefixes) {
        printPrefixStatsStd(prefix);
    }
}

void printPrefixStatsStd(IPPrefix prefix) {
    cout << prefix.getAddress() << "/" << prefix.getMaskNumber() << "\t";
    cout << prefix.getAllocated() << "\t\t";
    cout << prefix.getUsed() << "\t\t";
    cout << setprecision(3) << prefix.getUsage() * 100 << "%\t\t";
    cout << (prefix.getUsage() > 0.5 ? "YES" : "NO") << endl;
}

void printAllStatsNcurses() {
    printw("IP-Prefix\tMax-hosts\tAllocated\tUtilization\tOver50%\n");
    for (auto &prefix : g_args.prefixes) {
        printPrefixStatsNcurses(prefix);
    }
}

void printPrefixStatsNcurses(IPPrefix prefix) {
    printw("%s/%d\t", prefix.getAddress().c_str(), prefix.getMaskNumber());
    printw("%d\t\t", prefix.getAllocated());
    printw("%d\t\t", prefix.getUsed());
    printw("%.3f%%\t\t", prefix.getUsage() * 100);
    printw("%s\n", (prefix.getUsage() > 0.5 ? "YES" : "NO"));
}

int main(int argc, char *argv[]) {
    g_args = parseArguments(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];

    signal(SIGINT, sigint_handler);

    // syslog init
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    if (!g_args.fileName.empty()) { // read packets from file
        descr = pcap_open_offline(g_args.fileName.c_str(), errbuf);
    } else if (!g_args.interface.empty()) { // read packets from interface
        // 0 - promiscuous mode off, -1 - no timeout
        descr = pcap_open_live(g_args.interface.c_str(), BUFSIZ, 0, -1, errbuf);

        // start curses mode
        initscr();
        printAllStatsNcurses();
        refresh();
    }

    if (descr == NULL) {
        cout << "pcap_open_live(): " << errbuf << endl;
        exit(PCAP_OPEN);
    }

    if (pcap_compile(descr, &fp, "udp port 67 or udp port 68", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Error calling pcap_compile" << endl;
        pcap_close(descr);
        exit(PCAP_COMPILE);
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        cerr << "Error setting filter" << endl;
        pcap_close(descr);
        exit(PCAP_SETFILTER);
    }

    // 0 - infinite loop
    pcap_loop(descr, 0, packetCallback, NULL);

    if (!g_args.fileName.empty()) {
        printAllStatsStd();
    }

    cleanup();

    return SUCCESS;
}