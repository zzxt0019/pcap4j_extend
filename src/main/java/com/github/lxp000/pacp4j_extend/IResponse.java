package com.github.lxp000.pacp4j_extend;

public interface IResponse<REQ extends IRequest<REQ, RES>, RES extends IResponse<REQ, RES>> extends IPacket {
}
