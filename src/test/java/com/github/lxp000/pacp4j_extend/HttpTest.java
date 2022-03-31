package com.github.lxp000.pacp4j_extend;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lxp000.pacp4j_extend.http.HttpDecoder;
import com.github.lxp000.pacp4j_extend.http.HttpPacket;
import com.github.lxp000.pacp4j_extend.http.HttpRequest;
import com.github.lxp000.pacp4j_extend.http.HttpResponse;
import lombok.SneakyThrows;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

public class HttpTest {
    public static void main(String[] args) throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName("\\Device\\NPF_Loopback");
        PcapHandle pcapHandle = nif.openLive(99999,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10);
        pcapHandle.setFilter(
                "tcp port 8082"
                , BpfProgram.BpfCompileMode.OPTIMIZE);
        try {
            pcapHandle.loop(-1, new PacketListener() {
                private final HttpDecoder httpDecoder = new HttpDecoder();

                @SneakyThrows
                @Override
                public void gotPacket(Packet packet) {
                    HttpPacket httpPacket = null;
                    try {
                        httpPacket = httpDecoder.decode(packet);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    if (httpPacket instanceof HttpRequest) {
                        System.out.println("请求: " + new ObjectMapper().writeValueAsString(httpPacket));
                    } else if (httpPacket instanceof HttpResponse) {
                        System.out.println("响应: " + new ObjectMapper().writeValueAsString(httpPacket));
                    }
                }
            }); // COUNT设置为抓包个数，当为-1时无限抓包
        } catch (Exception e) {
            e.printStackTrace();
        }
        pcapHandle.close();
    }
}
