package com.github.lxp000.pacp4j_extend.http;

import com.github.lxp000.pacp4j_extend.IRequest;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@Data
public class HttpRequest extends HttpPacket implements IRequest<HttpRequest, HttpResponse> {
    protected String srcHost;  // 请求地址
    protected String dstHost;  // 目标地址
    protected Integer port;  // 端口
    protected String path;  // 访问路径
    protected Map<String, Object> parameters;  // 路径参数
    protected String httpMethod;  // 请求方式
}
