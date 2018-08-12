package org.redwater.fwsim.rules;

import java.util.List;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Map.Entry;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.Packets;
import org.redwater.fwsim.exceptions.InvalidFieldValueException;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;

public class TCPRule extends IPRule {
	private List<Entry<Integer, Integer>> srcPortRanges; 
	private boolean srcPortRangeMatchFlag;
	private List<Entry<Integer, Integer>> dstPortRanges;
	private boolean dstPortRangeMatchFlag;
	
	/**
	 * Construct the default IPRule.
	 */
	public TCPRule() {
		super();
		srcPortRanges = null;
		srcPortRangeMatchFlag = false;
		dstPortRanges = null;
		dstPortRangeMatchFlag = false;
	}
	
	/**
	 * Construct an IPRule using the list of fields and values.
	 * @throws UnhandledFieldNameException 
	 */
	public TCPRule(List<Entry<String, String>> parameters) throws UnhandledFieldNameException, InvalidFieldValueException {
		super();
		srcPortRanges = null;
		srcPortRangeMatchFlag = false;
		dstPortRanges = null;
		dstPortRangeMatchFlag = false;
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
		if (!Packets.containsTcpPacket(packet)) {
			return false;
		}
		TcpPacket tcpPacket = (TcpPacket)packet.get(TcpPacket.class);
		if (tcpPacket == null) {
			return false;
		}
		// Check source port ranges, if any.
		if (srcPortRanges != null) {
			int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
			boolean matched = false;
			for (Entry<Integer, Integer> r : srcPortRanges) {
				if (srcPort >= r.getKey() && srcPort <= r.getValue()) { 
					matched = true;
					break;
				}
			}
			if (!matched) {
				return false;
			} else if (srcPortRangeMatchFlag) {
				return false;
			}
		}
		// Check destination port ranges, if any.
		if (dstPortRanges != null) {
			int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
			boolean matched = false;
			for (Entry<Integer, Integer> r : srcPortRanges) {
				if (dstPort >= r.getKey() && dstPort <= r.getValue()) { 
					matched = true;
					break;
				}
			}
			if (!matched) {
				return false;
			} else if (dstPortRangeMatchFlag) {
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
		case "srcPort":
			int srcPortRangeStart;
			int srcPortRangeEnd;
			try {
				if (value.contains("-")) {
					String[] parts = value.split("-");
					if (parts.length != 2) {
						throw new InvalidFieldValueException(String.format("Invalid src port range '%s': src port range must have start and end separated by one '-'", value));
					}
					srcPortRangeStart = Integer.parseInt(parts[0]);
					srcPortRangeEnd = Integer.parseInt(parts[1]);
				} else {
					srcPortRangeStart = Integer.parseInt(value);
					srcPortRangeEnd = srcPortRangeStart;
				}
			}
			catch (NumberFormatException e) {
				throw new InvalidFieldValueException(String.format("Invalid src port range '%s': NumberFormatException %s", value, e.getMessage()));
			}
			if (srcPortRanges == null) {
				srcPortRanges = new ArrayList<>();
			}
			srcPortRanges.add(new SimpleEntry<>(srcPortRangeStart, srcPortRangeEnd));
			break;
		case "dstPort":
			int dstPortRangeStart;
			int dstPortRangeEnd;
			try {
				if (value.contains("-")) {
					String[] parts = value.split("-");
					if (parts.length != 2) {
						throw new InvalidFieldValueException(String.format("Invalid dst port range '%s': dst port range must have start and end separated by one '-'", value));
					}
					dstPortRangeStart = Integer.parseInt(parts[0]);
					dstPortRangeEnd = Integer.parseInt(parts[1]);
				} else {
					dstPortRangeStart = Integer.parseInt(value);
					dstPortRangeEnd = dstPortRangeStart;
				}
			}
			catch (NumberFormatException e) {
				throw new InvalidFieldValueException(String.format("Invalid dst port range '%s': NumberFormatException %s", value, e.getMessage()));
			}
			if (dstPortRanges == null) {
				dstPortRanges = new ArrayList<>();
			}
			dstPortRanges.add(new SimpleEntry<>(dstPortRangeStart, dstPortRangeEnd));
			break;
		default:
			super.setRuleField(fieldName, value);
			break;
		}
	}

}
