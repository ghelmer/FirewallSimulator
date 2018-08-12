package org.redwater.fwsim.layers;

import org.pcap4j.packet.Packet;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;

public interface IRule {
	/**
	 * Determine action for this rule on the packet.
	 * @param packet - Packet to check against this rule.
	 * @return a RuleAction or null
	 */
	public RuleActions getAction(Packet packet);
	
	/**
	 * Determine if this packet satisfies the rule.
	 * @param packet - Packet to check against this rule.
	 * @return true if matched, or false otherwise
	 */
	public boolean matchesRule(Packet packet);

	/**
	 * Set a field in a rule.
	 * @param fieldName - name of field to set
	 * @param value - value to use for field
	 * @throws UnhandledFieldNameException on unhandled field name
	 */
	public void setRuleField(String fieldName, String value) throws UnhandledFieldNameException;
}
