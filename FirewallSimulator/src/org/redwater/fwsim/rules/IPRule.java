package org.redwater.fwsim.rules;

import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.Packets;
import org.redwater.fwsim.exceptions.InvalidFieldValueException;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;

public class IPRule extends Rule {
	private SubnetInfo srcAddressMatch;
	private boolean srcAddressMatchFlag;
	private SubnetInfo dstAddressMatch;
	private boolean dstAddressMatchFlag;
	
	/**
	 * Construct the default IPRule.
	 */
	public IPRule() {
		super();
		srcAddressMatch = null;
		srcAddressMatchFlag = false;
		dstAddressMatch = null;
		dstAddressMatchFlag = false;
	}
	
	/**
	 * Construct an IPRule using the list of fields and values.
	 * @throws UnhandledFieldNameException 
	 */
	public IPRule(List<Entry<String, String>> parameters) throws UnhandledFieldNameException, InvalidFieldValueException {
		super();
		srcAddressMatch = null;
		srcAddressMatchFlag = false;
		dstAddressMatch = null;
		dstAddressMatchFlag = false;
		for (Entry<String, String> e : parameters) {
			setRuleField(e.getKey(), e.getValue());
		}
	}
	
	/**
	 * Determine if the packet matches this rule.
	 * @param packet Packet to evaluate.
	 * @return true if the packet matches all fields
	 */
	public boolean matchesRule(Packet packet) {
		if (!Packets.containsIpV4Packet(packet)) {
			return false;
		}
		IpPacket ipPacket = (IpPacket)packet.get(IpPacket.class);
		if (ipPacket == null) {
			return false;
		}
		// Check source address.
		if (srcAddressMatch != null) {
			if (!srcAddressMatch.isInRange(ipPacket.getHeader().getSrcAddr().getHostAddress())) {
				return false;
			} else if (srcAddressMatchFlag) {
				return false;
			}
		}
		// Check destination address.
		if (dstAddressMatch != null) {
			if (!dstAddressMatch.isInRange(ipPacket.getHeader().getDstAddr().getHostAddress())) {
				return false;
			} else if (dstAddressMatchFlag) {
				return false;
			}
		}
		// So far, this rule matches. Evaluate the superclass on the packet.
		return super.matchesRule(packet);
	}
	
	/**
	 * Rule field set method implementation for IP packet matches.
	 * @param fieldName - name of rule field to set
	 * @param value - value to use for field
	 * @throws UnhandledFieldNameException always
	 */
	public void setRuleField(String fieldName, String value) throws UnhandledFieldNameException, InvalidFieldValueException {
		switch (fieldName) {
		case "srcAddress":
			srcAddressMatch = new SubnetUtils(value).getInfo();
			break;
		case "dstAddress":
			dstAddressMatch = new SubnetUtils(value).getInfo();
			break;
		default:
			super.setRuleField(fieldName, value);
			break;
		}
	}

}
