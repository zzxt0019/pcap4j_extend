package com.github.lxp000.pacp4j_extend;

import org.pcap4j.packet.Packet;

public interface IDecoder<IPacket> {
    IPacket decode(Packet packet);
}
