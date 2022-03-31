package com.github.lxp000.pacp4j_extend;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class Demo {
    public static void main(String[] args) throws Exception {
        PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();
        PcapHandle pcapHandle = nif.openLive(99999,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10);
        pcapHandle.loop(-1, new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                System.out.println(packet);
            }
        });
        pcapHandle.close();
    }
}
