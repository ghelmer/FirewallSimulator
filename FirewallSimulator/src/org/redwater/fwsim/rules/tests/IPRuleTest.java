package org.redwater.fwsim.rules.tests;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Map.Entry;
import java.net.Inet4Address;
import java.util.AbstractMap.SimpleEntry;

import org.junit.Before;
import org.junit.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.redwater.fwsim.rules.IPRule;

public class IPRuleTest {
	private IPRule ipRule1; 
	private IPRule ipRule2;
	private IPRule ipRule3; 
	private Packet packet1;
	private Packet packet2;


	@Before
	public void setUp() throws Exception {
		ArrayList<Entry<String, String>> parameters1 = new ArrayList<>();
		parameters1.add(new SimpleEntry<>("srcAddress", "192.168.1.0/24"));
		parameters1.add(new SimpleEntry<>("dstAddress", "0.0.0.0/0"));
		parameters1.add(new SimpleEntry<>("action", "accept"));
		ipRule1 = new IPRule(parameters1);

		ArrayList<Entry<String, String>> parameters2 = new ArrayList<>();
		parameters2.add(new SimpleEntry<>("srcAddress", "0.0.0.0/0"));
		parameters2.add(new SimpleEntry<>("dstAddress", "192.168.1.0/24"));
		parameters2.add(new SimpleEntry<>("action", "deny"));
		ipRule2 = new IPRule(parameters2);
		
		ArrayList<Entry<String, String>> parameters3 = new ArrayList<>();
		parameters3.add(new SimpleEntry<>("action", "accept"));
		ipRule3 = new IPRule(parameters3);
		
		IpV4Packet.Builder packetBuilder1 = new IpV4Packet.Builder();
		packetBuilder1.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte)0))
			.ttl((byte)64)
			 // Not a valid TCP segment -- no payload
			.protocol(IpNumber.TCP)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.dontFragmentFlag(true)
			.paddingAtBuild(true);
		packetBuilder1.srcAddr((Inet4Address) Inet4Address.getByName("192.168.1.1"));
		packetBuilder1.dstAddr((Inet4Address) Inet4Address.getByName("1.2.3.4"));
		packet1 = packetBuilder1.build();

		IpV4Packet.Builder packetBuilder2 = new IpV4Packet.Builder();
		packetBuilder2.version(IpVersion.IPV4)
			.tos(IpV4Rfc1349Tos.newInstance((byte)0))
			.ttl((byte)64)
			// Not a valid TCP segment -- no payload
			.protocol(IpNumber.TCP)
			.correctChecksumAtBuild(true)
			.correctLengthAtBuild(true)
			.dontFragmentFlag(true)
			.paddingAtBuild(true);
		packetBuilder2.srcAddr((Inet4Address) Inet4Address.getByName("1.2.3.4"));
		packetBuilder2.dstAddr((Inet4Address) Inet4Address.getByName("192.168.1.1"));
		packet2 = packetBuilder2.build();
	}

	@Test
	public void test() {
		assertTrue("packet1 did not match rule 1 src 192.168.1.0/24 dst 0.0.0.0/0",
				ipRule1.matchesRule(packet1));
		assertTrue("packet2 did not match rule 2 src 0.0.0.0/0 dst 192.168.1.0/24",
				ipRule2.matchesRule(packet2));
		assertTrue("packet1 did not match rule 3 (no src or dst)",
				ipRule3.matchesRule(packet1));

		assertFalse("packet2 unexpectedly matched rule 1src 192.168.1.0/24 dst 0.0.0.0/0",
				ipRule1.matchesRule(packet2));
		assertFalse("packet1 unexpectedly matched rule 2 src 0.0.0.0/0 dst 192.168.1.0/24",
				ipRule2.matchesRule(packet1));
		assertTrue("packet2 did not match rule 3 (not src or dst)",
				ipRule3.matchesRule(packet2));
	}
}
