#include <iostream>
#include "stdlib.h"
#include <PcapLiveDeviceList.h>
#include "SystemUtils.h"
#include <IPv4Layer.h>
#include <set>

struct PacketStats
{
    int ethPacketCount;
    int ipv4PacketCount;
    int ipv6PacketCount;
    int tcpPacketCount;
    int udpPacketCount;
    int dnsPacketCount;
    int httpPacketCount;
    int sslPacketCount;

    std::set<std::string> sourceIPs;
    std::set<std::string> destIPs;

    void clear() { ethPacketCount = 0; ipv4PacketCount = 0; ipv6PacketCount = 0; tcpPacketCount = 0; udpPacketCount = 0; tcpPacketCount = 0; dnsPacketCount = 0; httpPacketCount = 0; sslPacketCount = 0; }

    PacketStats() { clear(); }

    void consumePacket(pcpp::Packet& packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4)) {
            ipv4PacketCount++;
            pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
            if (ipv4Layer) {
                sourceIPs.insert(ipv4Layer->getSrcIPAddress().toString());
                destIPs.insert(ipv4Layer->getDstIPAddress().toString());
            }
        }
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    void printToConsole()
    {
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl
            << "IPv4 packet count:     " << ipv4PacketCount << std::endl
            << "IPv6 packet count:     " << ipv6PacketCount << std::endl
            << "TCP packet count:      " << tcpPacketCount << std::endl
            << "UDP packet count:      " << udpPacketCount << std::endl
            << "DNS packet count:      " << dnsPacketCount << std::endl
            << "HTTP packet count:     " << httpPacketCount << std::endl
            << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    // Extract the stats object from the cookie
    PacketStats* stats = (PacketStats*)cookie;

    // Parse the raw packet
    pcpp::Packet parsedPacket(packet);

    // Collect stats from the packet
    stats->consumePacket(parsedPacket);

    // Add event handling functionality
    if (parsedPacket.isPacketOfType(pcpp::HTTP) || parsedPacket.isPacketOfType(pcpp::SSL)) {
        std::cout << "Potential security event detected: HTTP/SSL packet captured." << std::endl;
    }
}

int main(int argc, char* argv[])
{
	// Get the interface name from the user
	std::string interfaceIPAddr;
    std::cout << "Please enter the interface IP address to capture packets from: ";
    std::cin >> interfaceIPAddr;

    // Find the interface by IP address
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
    if (dev == NULL)
    {
        std::cerr << "Cannot find the interface with an IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
        return 1;
    }

    // Print device info
    std::cout
        << "Preparing to capture network packets on interface:" << std::endl
        << "   Interface name:        " << dev->getName() << std::endl
        << "   Interface description: " << dev->getDesc() << std::endl
        << "   MAC address:           " << dev->getMacAddress() << std::endl
        << "   Default gateway:       " << dev->getDefaultGateway() << std::endl
        << "   Interface MTU:         " << dev->getMtu() << std::endl;

    if (dev->getDnsServers().size() > 0)
        std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;

    if (!dev->open())
    {
        std::cerr << "Cannot open the device" << std::endl;
        return 1;
    }

    PacketStats stats;

    while (true) {
        stats.clear();
        std::cout << std::endl << "Starting asynchronous packet capture..." << std::endl;

        // Start packet capture in asynchronous mode. Provide a callback function to call when a packet is captured and the stats object as the cookie.
        dev->startCapture(onPacketArrives, &stats);
        // Sleep for 10 seconds in the main thread; meanwhile, packets are captured in the background
        pcpp::multiPlatformSleep(10);

        // Stop capturing packets
        dev->stopCapture();
        // Print the results
        std::cout << "Capture results:" << std::endl;
        stats.printToConsole();

        std::cout << "Source IP addresses seen in captured packets:" << std::endl;
        for (const std::string& sourceIP : stats.sourceIPs) {
            std::cout << "Source IP: " << sourceIP << std::endl;
        }

        std::cout << "Destination IP addresses seen in captured packets:" << std::endl;
        for (const std::string& destIP : stats.destIPs) {
            std::cout << "Destination IP: " << destIP << std::endl;
        }
    }
}
