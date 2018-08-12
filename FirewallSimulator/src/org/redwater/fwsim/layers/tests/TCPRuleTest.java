package org.redwater.fwsim.layers.tests;

import java.net.Inet4Address;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpEndOfOptionList;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.TcpTimestampsOption;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.redwater.fwsim.layers.TCPRule;

public class TCPRuleTest {
	private TCPRule tcpRule1; 
	private TCPRule tcpRule2;
	private TCPRule tcpRule3; 
	private Packet packet1;
	private Packet packet2;

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

	@Before
	public void setUp() throws Exception {
		ArrayList<Entry<String, String>> parameters1 = new ArrayList<>();
		parameters1.add(new SimpleEntry<>("srcAddress", "192.168.1.0/24"));
		parameters1.add(new SimpleEntry<>("dstAddress", "0.0.0.0/0"));
		parameters1.add(new SimpleEntry<>("srcPort", "25"));
		parameters1.add(new SimpleEntry<>("action", "accept"));
		tcpRule1 = new TCPRule(parameters1);

		ArrayList<Entry<String, String>> parameters2 = new ArrayList<>();
		parameters2.add(new SimpleEntry<>("srcAddress", "0.0.0.0/0"));
		parameters2.add(new SimpleEntry<>("dstAddress", "192.168.1.0/24"));
		parameters1.add(new SimpleEntry<>("dstPort", "25"));
		parameters2.add(new SimpleEntry<>("action", "deny"));
		tcpRule2 = new TCPRule(parameters2);
		
		ArrayList<Entry<String, String>> parameters3 = new ArrayList<>();
		parameters3.add(new SimpleEntry<>("action", "accept"));
		tcpRule3 = new TCPRule(parameters3);
		
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
		packet1 = packetBuilder1.build();

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
		packetBuilder2.srcAddr((Inet4Address) Inet4Address.getByName("1.2.3.4"));
		packetBuilder2.dstAddr((Inet4Address) Inet4Address.getByName("192.168.1.1"));
		packet2 = packetBuilder2.build();
	}

	@Test
	public void test() {
		assertTrue("packet1 did not match rule 1 src 192.168.1.0/24 dst 0.0.0.0/0",
				tcpRule1.matchesRule(packet1));
		assertTrue("packet2 did not match rule 2 src 0.0.0.0/0 dst 192.168.1.0/24",
				tcpRule2.matchesRule(packet2));
		assertTrue("packet1 did not match rule 3 (no src or dst)",
				tcpRule3.matchesRule(packet1));

		assertFalse("packet2 unexpectedly matched rule 1src 192.168.1.0/24 dst 0.0.0.0/0",
				tcpRule1.matchesRule(packet2));
		assertFalse("packet1 unexpectedly matched rule 2 src 0.0.0.0/0 dst 192.168.1.0/24",
				tcpRule2.matchesRule(packet1));
		assertTrue("packet2 did not match rule 3 (not src or dst)",
				tcpRule3.matchesRule(packet2));
	}
}
