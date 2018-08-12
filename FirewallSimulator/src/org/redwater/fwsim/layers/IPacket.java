package org.redwater.fwsim.layers;

public interface IPacket {
	public Byte[] getPayload();
	public void setPayload(Byte[] payload);
	public Byte[] getHeader();
	public void setHeader(Byte[] payload);
	public String getId();
	public void setId();
}
