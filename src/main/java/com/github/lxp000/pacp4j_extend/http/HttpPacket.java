package com.github.lxp000.pacp4j_extend.http;

import com.github.lxp000.pacp4j_extend.IPacket;
import lombok.Data;

import java.util.Date;
import java.util.Map;

@Data
public abstract class HttpPacket implements IPacket {
    protected boolean complete;  // 包是否完整
    protected Date packetTime;  // 抓包时间
    protected Long timeId;  // 请求时间id
    /**
     * ackNum相同 => 是同一条请求/响应
     * 请求的ackNum与响应的seqNum相同 => 对应一组
     */
    protected Long ackNum;
    protected Map<String, Object> headers;  // 请求头
    protected String body;  // 请求体
}
