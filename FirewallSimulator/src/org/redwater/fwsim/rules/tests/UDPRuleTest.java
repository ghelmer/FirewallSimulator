package org.redwater.fwsim.rules.tests;

import static org.junit.Assert.*;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import org.junit.Before;
import org.junit.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.redwater.fwsim.rules.UDPRule;

public class UDPRuleTest {
	private UDPRule udpRule1; 
	private UDPRule udpRule2;
	private UDPRule udpRule3; 
	private Packet packet1;
	private Packet packet2;

	/**
	 * Create a testing UDP segment.
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
		ArrayList<Entry<String, String>> parameters1 = new ArrayList<>();
		parameters1.add(new SimpleEntry<>("srcAddress", "192.168.1.0/24"));
		parameters1.add(new SimpleEntry<>("dstAddress", "0.0.0.0/0"));
		parameters1.add(new SimpleEntry<>("srcPort", "53"));
		parameters1.add(new SimpleEntry<>("action", "accept"));
		udpRule1 = new UDPRule(parameters1);

		ArrayList<Entry<String, String>> parameters2 = new ArrayList<>();
		parameters2.add(new SimpleEntry<>("srcAddress", "0.0.0.0/0"));
		parameters2.add(new SimpleEntry<>("dstAddress", "192.168.1.0/24"));
		parameters1.add(new SimpleEntry<>("dstPort", "53"));
		parameters2.add(new SimpleEntry<>("action", "deny"));
		udpRule2 = new UDPRule(parameters2);
		
		ArrayList<Entry<String, String>> parameters3 = new ArrayList<>();
		parameters3.add(new SimpleEntry<>("action", "accept"));
		udpRule3 = new UDPRule(parameters3);
		
		IpV4Packet.Builder packetBuilder1 = new IpV4Packet.Builder();
		Inet4Address srcAddr = (Inet4Address) Inet4Address.getByName("192.168.1.1");
		Inet4Address dstAddr = (Inet4Address) Inet4Address.getByName("1.2.3.4");

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
		packet1 = packetBuilder1.build();

		IpV4Packet.Builder packetBuilder2 = new IpV4Packet.Builder();
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
		packetBuilder2.srcAddr((Inet4Address) Inet4Address.getByName("1.2.3.4"));
		packetBuilder2.dstAddr((Inet4Address) Inet4Address.getByName("192.168.1.1"));
		packet2 = packetBuilder2.build();
	}

	@Test
	public void test() {
		assertTrue("packet1 did not match rule 1 src 192.168.1.0/24 dst 0.0.0.0/0",
				udpRule1.matchesRule(packet1));
		assertTrue("packet2 did not match rule 2 src 0.0.0.0/0 dst 192.168.1.0/24",
				udpRule2.matchesRule(packet2));
		assertTrue("packet1 did not match rule 3 (no src or dst)",
				udpRule3.matchesRule(packet1));

		assertFalse("packet2 unexpectedly matched rule 1src 192.168.1.0/24 dst 0.0.0.0/0",
				udpRule1.matchesRule(packet2));
		assertFalse("packet1 unexpectedly matched rule 2 src 0.0.0.0/0 dst 192.168.1.0/24",
				udpRule2.matchesRule(packet1));
		assertTrue("packet2 did not match rule 3 (not src or dst)",
				udpRule3.matchesRule(packet2));
	}
}
