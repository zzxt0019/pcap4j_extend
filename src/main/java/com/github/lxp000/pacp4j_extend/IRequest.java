package com.github.lxp000.pacp4j_extend;

public interface IRequest<REQ extends IRequest<REQ, RES>, RES extends IResponse<REQ, RES>> extends IPacket {
}
