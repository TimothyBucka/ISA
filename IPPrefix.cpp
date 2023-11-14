// Made by: Timotej Bucka (xbucka00)

#include "dhcp-stats.hpp"

IPPrefix::IPPrefix() {
    this->address = "";
    this->bitAddress = 0;
    this->broadcastBitAddress = 0;
    this->maskNumber = 0;
    this->bitMask = 0;
    this->allocated = 0;
    this->used = 0;
    this->usage = 0;
    this->logged = false;
}

IPPrefix::IPPrefix(string prefix) {
    size_t slash = prefix.find('/');
    if (slash == string::npos) {
        throw INVALID_PREFIX;
    }

    this->address = prefix.substr(0, slash);

    // convert string address to uint32_t
    int ret = inet_pton(AF_INET, this->address.c_str(), &(this->bitAddress));
    if (ret != 1) {
        throw INVALID_PREFIX;   // address is not valid
    }
    this->bitAddress = ntohl(this->bitAddress); // get address in correct order

    try {
        this->maskNumber = stoi(prefix.substr(slash + 1));
    } catch ( ... ) {
        throw INVALID_PREFIX;   // mask number is not valid
    }

    // broadcast address
    this->broadcastBitAddress = this->bitAddress | ((1 << (IP4_ADDR_LEN - this->maskNumber)) - 1);

    // create bit mask
    this->bitMask = (1 << this->maskNumber) - 1;
    this->bitMask <<= (IP4_ADDR_LEN - this->maskNumber); // shift to left

    this->allocated = (1 << (IP4_ADDR_LEN - this->maskNumber)) - 2; // -2 because of network and broadcast
    if (this->allocated <= 0) {
        throw INVALID_PREFIX;
    }

    this->used = 0;
    this->usage = 0;
    this->logged = false;
}

void IPPrefix::addUsed(int toAdd) {
    this->used += toAdd;
    this->usage = (float) this->used / (float) this->allocated;
}

void IPPrefix::setLogged(bool logged) {
    this->logged = logged;
}

string IPPrefix::getAddress() { return this->address; }
uint32_t IPPrefix::getBitAddress() { return this->bitAddress; }
uint32_t IPPrefix::getBroadcastBitAddress() { return this->broadcastBitAddress; }
int IPPrefix::getMaskNumber() { return this->maskNumber; }
uint32_t IPPrefix::getBitMask() { return this->bitMask; }
int IPPrefix::getAllocated() { return this->allocated; }
int IPPrefix::getUsed() { return this->used; }
float IPPrefix::getUsage() { return this->usage; }
bool IPPrefix::getLogged() { return this->logged; }
