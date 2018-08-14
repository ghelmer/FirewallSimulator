# Firewall Simulator

## Simple packet filtering firewall simulator code

This project under construction implements a simple rule element parser and evaluator to match UDP or TCP packets and determine whether to allow or deny them. Because I haven't found a simulator that can show, packet by packet, how a packet filtering firewall evaluates rules and determines whether to allow network traffic, I decided to build a simple project that can be used to develop firewall rules and test them on packets from a network traffic capture.

These concepts are meant to be generally applicable to a packet filter firewall. Different implementations, such as Linux IPTables, FreeBSD ipfw, Cisco Extended ACLs, etc. vary in syntax, configuration methodology, and features. However, the basic functionality in all packet filter firewalls enables selectively matching packets based on protocols, IP addresses, and TCP or UDP port numbers, and that is the focus of the code in this project.

This project depends on [Pcap4J](https://www.pcap4j.org/) for network packets and [Apache Commons](https://commons.apache.org/) projects. It uses Maven for the build.

## Features

Not many features so far. As of now, there are classes to parse TCP and UDP port ranges (`srcPort` and `dstPort` expressions) and IPv4 CIDR blocks (`srcAddress` and `dstAddress`). Additionally functionality planned includes a simple text interface to specify & compile rules, and an interface to open a pcap packet capture file and test the rules on the packets in the file.
