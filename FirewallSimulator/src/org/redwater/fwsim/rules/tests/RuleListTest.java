package org.redwater.fwsim.rules.tests;

import static org.junit.Assert.*;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.junit.Before;
import org.junit.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpEndOfOptionList;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpTimestampsOption;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.redwater.fwsim.rules.IRule;
import org.redwater.fwsim.rules.RuleList;

public class RuleListTest {
	private RuleList rules;
	private RuleList rulesFromScanner;
	private Packet tcpPacket1;
	private Packet tcpPacket2;
	private Packet udpPacket1;
	private Packet udpPacket2;

	/**
	 * Create a testing TCP segment.
	 * @param direction false if client->server, false if server->client
	 * @return constructed TCP packet
	 */
	private static TcpPacket buildTCPRuleTestTCPPacket(boolean direction) {
		TcpPort srcPort; 
		TcpPort dstPort; 
		int sequenceNumber; 
		int acknowledgmentNumber; 
		byte dataOffset; 
		byte reserved; 
		boolean urg; 
		boolean ack; 
		boolean psh; 
		boolean rst; 
		boolean syn; 
		boolean fin; 
		short window; 
		short checksum; 
		short urgentPointer; 
		List<TcpOption> options; 
		byte[] padding;

		if (!direction) {
			srcPort = TcpPort.SMTP; 
			dstPort = TcpPort.getInstance((short)9876); 
			sequenceNumber = 1234567; 
			acknowledgmentNumber = 7654321;
		} else {
			srcPort =  TcpPort.getInstance((short)9876);
			dstPort = TcpPort.SMTP; 
			sequenceNumber = 7654321; 
			acknowledgmentNumber = 1234567;

		}
		dataOffset = 15; 
		reserved = (byte)11; 
		urg = false; 
		ack = true; 
		psh = false; 
		rst = true; 
		syn = false; 
		fin = true; 
		window = (short)9999; 
		checksum = (short)0xABCD; 
		urgentPointer = (short)1111; 

		options = new ArrayList<TcpOption>(); 
		options.add( 
				new TcpTimestampsOption.Builder() 
				.tsValue(200) 
				.tsEchoReply(111) 
				.correctLengthAtBuild(true) 
				.build() 
				); 
		options.add(TcpEndOfOptionList.getInstance()); 

		padding = new byte[] { (byte)0xaa }; 

		UnknownPacket.Builder unknownb = new UnknownPacket.Builder(); 
		unknownb.rawData(new byte[] { (byte)0, (byte)1, (byte)2, (byte)3 }); 

		TcpPacket.Builder b = new TcpPacket.Builder(); 
		b.dstPort(dstPort) 
		.srcPort(srcPort) 
		.sequenceNumber(sequenceNumber) 
		.acknowledgmentNumber(acknowledgmentNumber) 
		.dataOffset(dataOffset) 
		.reserved(reserved) 
		.urg(urg) 
		.ack(ack) 
		.psh(psh) 
		.rst(rst) 
		.syn(syn) 
		.fin(fin) 
		.window(window) 
		.checksum(checksum) 
		.urgentPointer(urgentPointer) 
		.options(options) 
		.padding(padding) 
		.correctChecksumAtBuild(false) 
		.correctLengthAtBuild(false) 
		.paddingAtBuild(false) 
		.payloadBuilder(unknownb); 

		return b.build(); 
	}
	
	/**
	 * Create a testing UDP datagram.
	 * @param direction false if client->server, false if server->client
	 * @return constructed UDP packet
	 */
	private static UdpPacket buildUDPRuleTestUDPPacket(boolean direction) {
		UdpPort srcPort; 
		UdpPort dstPort; 
		short checksum;

		if (!direction) {
			srcPort = UdpPort.DOMAIN;
			dstPort = UdpPort.getInstance((short)9876); 
		} else {
			srcPort = UdpPort.getInstance((short)9876);
			dstPort = UdpPort.DOMAIN; 

		}
		checksum = (short)0xABCD; 
		UnknownPacket.Builder unknownb = new UnknownPacket.Builder(); 
		unknownb.rawData(new byte[] { (byte)0, (byte)1, (byte)2, (byte)3 }); 

		UdpPacket.Builder b = new UdpPacket.Builder(); 
		b.dstPort(dstPort) 
		.srcPort(srcPort) 
		.checksum(checksum) 
		.correctChecksumAtBuild(false) 
		.correctLengthAtBuild(false) 
		.payloadBuilder(unknownb); 

		return b.build(); 
	}

	@Before
	public void setUp() throws Exception {
		IRule r;
		rules = new RuleList();
		r = rules.addRule("tcp srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0 srcPort 25 action accept");
		r.setRuleMetadata("TCP rule 1");
		r = rules.addRule("tcp srcAddress 0.0.0.0/0 dstAddress 192.168.1.0/24 dstPort 25 action deny");
		r.setRuleMetadata("TCP rule 2");
		r = rules.addRule("tcp action accept");
		r.setRuleMetadata("TCP rule 3");
		r = rules.addRule("udp srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0 srcPort 53 action accept");
		r.setRuleMetadata("UDP rule 1");
		r = rules.addRule("udp srcAddress 0.0.0.0/0 dstAddress 192.168.1.0/24 dstPort 53 action deny");
		r.setRuleMetadata("UDP rule 2");
		r = rules.addRule("udp action accept");
		r.setRuleMetadata("UDP rule 3");
		
		// Test parsing a list of lines of text.
		String[] lines = {
				"# This is a comment line",
				"tcp srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0 srcPort 25 action accept",
				"tcp srcAddress 0.0.0.0/0 dstAddress 192.168.1.0/24 dstPort 25 action deny",
				"tcp action accept",
				"udp srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0 srcPort 53 action accept",
				"udp srcAddress 0.0.0.0/0 dstAddress 192.168.1.0/24 dstPort 53 action deny",
				"udp action accept # inline comment"
		};
		rulesFromScanner = new RuleList();
		rulesFromScanner.parse(new Scanner(String.join("\n", lines)));

		/*
		 * Build TCP packets for testing.
		 */
		IpV4Packet.Builder packetBuilder1 = new IpV4Packet.Builder();
		Inet4Address srcAddr = (Inet4Address) Inet4Address.getByName("192.168.1.1");
		Inet4Address dstAddr = (Inet4Address) Inet4Address.getByName("1.2.3.4");
		packetBuilder1.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte)0))
			.ttl((byte)64)
			 // Not a valid TCP segment -- no payload
			.protocol(IpNumber.TCP)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.dontFragmentFlag(true)
			.paddingAtBuild(true)
			.payloadBuilder(
					buildTCPRuleTestTCPPacket(false).getBuilder() 
		              .correctChecksumAtBuild(true) 
		              .correctLengthAtBuild(true) 
		              .paddingAtBuild(true)
		              .dstAddr(dstAddr) 
		              .srcAddr(srcAddr)
		          );
		packetBuilder1.srcAddr(srcAddr);
		packetBuilder1.dstAddr(dstAddr);
		tcpPacket1 = packetBuilder1.build();

		IpV4Packet.Builder packetBuilder2 = new IpV4Packet.Builder();
		srcAddr = (Inet4Address) Inet4Address.getByName("1.2.3.4");
		dstAddr = (Inet4Address) Inet4Address.getByName("192.168.1.1");
		packetBuilder2.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte)0))
			.ttl((byte)64)
			// Not a valid TCP segment -- no payload
			.protocol(IpNumber.TCP)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.dontFragmentFlag(true)
			.paddingAtBuild(true)
			.payloadBuilder(
					buildTCPRuleTestTCPPacket(true).getBuilder() 
		              .correctChecksumAtBuild(true) 
		              .correctLengthAtBuild(true) 
		              .paddingAtBuild(true) 
		              .dstAddr(dstAddr) 
		              .srcAddr(srcAddr)
		          );
		packetBuilder2.srcAddr(srcAddr);
		packetBuilder2.dstAddr(dstAddr);
		tcpPacket2 = packetBuilder2.build();
		
		/*
		 * Build UDP packets for testing.
		 */

		packetBuilder1 = new IpV4Packet.Builder();
		srcAddr = (Inet4Address) Inet4Address.getByName("192.168.1.1");
		dstAddr = (Inet4Address) Inet4Address.getByName("1.2.3.4");
		packetBuilder1.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte)0))
			.ttl((byte)64)
			 // Not a valid UDP segment -- no payload
			.protocol(IpNumber.UDP)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.dontFragmentFlag(true)
			.paddingAtBuild(true)
			.payloadBuilder(
					buildUDPRuleTestUDPPacket(false).getBuilder() 
		              .correctChecksumAtBuild(true) 
		              .correctLengthAtBuild(true) 
		              .dstAddr(dstAddr) 
		              .srcAddr(srcAddr)
		          );
		packetBuilder1.srcAddr(srcAddr);
		packetBuilder1.dstAddr(dstAddr);
		udpPacket1 = packetBuilder1.build();

		packetBuilder2 = new IpV4Packet.Builder();
		srcAddr = (Inet4Address) Inet4Address.getByName("1.2.3.4");
		dstAddr = (Inet4Address) Inet4Address.getByName("192.168.1.1");
		packetBuilder2.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte)0))
			.ttl((byte)64)
			// Not a valid UDP segment -- no payload
			.protocol(IpNumber.UDP)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.dontFragmentFlag(true)
			.paddingAtBuild(true)
			.payloadBuilder(
					buildUDPRuleTestUDPPacket(true).getBuilder() 
		              .correctChecksumAtBuild(true) 
		              .correctLengthAtBuild(true) 
		              .dstAddr(dstAddr) 
		              .srcAddr(srcAddr)
		          );
		packetBuilder2.srcAddr(srcAddr);
		packetBuilder2.dstAddr(dstAddr);
		udpPacket2 = packetBuilder2.build();

	}

	@Test
	public void test() {
		IRule r = rules.checkRules(udpPacket1);
		assertEquals(r.getRuleMetadata(), "UDP rule 1");
		System.out.printf("udpPacket1 matched rule %s\n", r.toString());
		r = rules.checkRules(udpPacket2);
		assertEquals(r.getRuleMetadata(), "UDP rule 2");
		System.out.printf("udpPacket2 matched rule %s\n", r.toString());
		r = rules.checkRules(tcpPacket1);
		assertEquals(r.getRuleMetadata(), "TCP rule 1");
		System.out.printf("tcpPacket1 matched rule %s\n", r.toString());
		r = rules.checkRules(tcpPacket2);
		assertEquals(r.getRuleMetadata(), "TCP rule 2");
		System.out.printf("tcpPacket2 matched rule %s\n", r.toString());
	}

	@Test
	public void test2() {		
		IRule r = rulesFromScanner.checkRules(udpPacket1);
		assertEquals(r.getRuleMetadata(), "Line 5");
		System.out.printf("udpPacket1 matched fromScanner rule %s %s\n", r.getRuleMetadata(), r.toString());
		r = rulesFromScanner.checkRules(udpPacket2);
		assertEquals(r.getRuleMetadata(), "Line 6");
		System.out.printf("udpPacket2 matched fromScanner rule %s %s\n", r.getRuleMetadata(), r.toString());
		r = rulesFromScanner.checkRules(tcpPacket1);
		assertEquals(r.getRuleMetadata(), "Line 2");
		System.out.printf("tcpPacket1 matched fromScanner rule %s %s\n", r.getRuleMetadata(), r.toString());
		r = rulesFromScanner.checkRules(tcpPacket2);
		assertEquals(r.getRuleMetadata(), "Line 3");
		System.out.printf("tcpPacket2 matched fromScanner rule %s %s\n", r.getRuleMetadata(), r.toString());
	}
}
