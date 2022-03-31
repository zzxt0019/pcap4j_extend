package com.github.lxp000.pacp4j_extend.http;

import com.github.lxp000.pacp4j_extend.IResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class HttpResponse extends HttpPacket implements IResponse<HttpRequest, HttpResponse> {
    protected Long seqNum;  // 和请求ackNum对应同一组
    protected Integer resCode;  // 响应码
}
