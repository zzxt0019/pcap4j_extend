package com.github.lxp000.pacp4j_extend.http;

import com.github.lxp000.pacp4j_extend.IDecoder;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.util.ReferenceCountUtil;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * HTTP解码器
 */
public class HttpDecoder implements IDecoder<HttpPacket> {
    private static final long timeout = 10_0000;  // ms
    private final Deque<HttpMessage> messages = new LinkedList<>();
    private static final ByteBuf HTTP = Unpooled.wrappedBuffer("HTTP/1.1".getBytes(StandardCharsets.UTF_8));
    private static final ByteBuf line1 = Unpooled.wrappedBuffer("\r\n".getBytes(StandardCharsets.UTF_8));
    private static final ByteBuf line2 = Unpooled.wrappedBuffer("\r\n\r\n".getBytes(StandardCharsets.UTF_8));

    /**
     * TCP包 解码HTTP<br>
     * 1. 首先通过{@link #match(TcpPacket)}判断当前包是新包还是后续包
     * 2. 若为后续包, 通过{@link #packetAppend(HttpPacket, ByteBuf)}拼接, 直到为完整包时发送
     * 3. 若为新包, 解析HTTP状态行和头部行
     *
     * @param packet TCP包
     * @return {@link HttpNull} 解码错误(或非完整包) 可以不做处理<br>
     * {@link HttpRequest} 完整的请求<br>
     * {@link HttpResponse} 完整的响应
     */
    public HttpPacket decode(Packet packet) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getPayload() != null && tcpPacket.getPayload().getRawData() != null && tcpPacket.getPayload().getRawData().length > 0) {
            HttpPacket httpPacket = match(tcpPacket);
            if (httpPacket == null) {  // 未匹配成功, 按照新包解析
                ByteBuf rawData = Unpooled.wrappedBuffer(tcpPacket.getPayload().getRawData());
                if (rawData.readableBytes() < 3) {
                    return new HttpNull();
                }
                int bodyIndex = ByteBufUtil.indexOf(line2, rawData);  // body前面\r\n\r\n的位置
                if (bodyIndex == -1) {
                    return new HttpNull();
                }
                int headersIndex = ByteBufUtil.indexOf(line1, rawData);  // HTTP头部行前面\r\n的位置
                ByteBuf statusLine = rawData.slice(0, headersIndex);  // HTTP状态行
                readStatusLine(statusLine);
                List<ByteBuf> httpLines = split(rawData.slice(0, bodyIndex),  // body前的内容  现在rawData为 "\r\nBODY"
                        line1, 2);  // [0]为HTTP状态行和首部行 [1]为HTTP实体
                httpPacket = readStatusLine(httpLines.get(0));  // 解析HTTP状态行
                if (httpPacket instanceof HttpNull) {
                    return new HttpNull();  // 此处已经完成拼包匹配 若还是未解析出HTTP协议 说明这个包是错的
                }
                httpPacket.setPacketTime(new Date());
                httpPacket.setAckNum(tcpPacket.getHeader().getAcknowledgmentNumberAsLong());
                if (httpLines.size() == 2) {
                    List<ByteBuf> headerLines = split(httpLines.get(1), line1);  // HTTP首部行
                    httpPacket.setHeaders(readHeaderLines(headerLines));  // 解析HTTP首部行
                }

                packetAppend(httpPacket, rawData.slice(bodyIndex + line2.readableBytes(),
                        rawData.readableBytes() - bodyIndex - line2.readableBytes()));
                // 其他TCP参数
                if (httpPacket instanceof HttpRequest) {
                    HttpRequest httpRequest = (HttpRequest) httpPacket;
                    httpRequest.setPacketTime(new Date());
                    if (ipV4Packet != null) {
                        httpRequest.setSrcHost(ipV4Packet.getHeader().getSrcAddr().getHostAddress());
                        httpRequest.setDstHost(ipV4Packet.getHeader().getDstAddr().getHostAddress());
                    }
                    httpRequest.setPort(tcpPacket.getHeader().getDstPort().valueAsInt());
                } else if (httpPacket instanceof HttpResponse) {
                    HttpResponse httpResponse = (HttpResponse) httpPacket;
                    httpResponse.setSeqNum(tcpPacket.getHeader().getSequenceNumberAsLong());
                }
                httpPacket = match(httpPacket);
                if (httpPacket.isComplete()) {  // 初始完整的请求/响应 可以发送
                    return httpPacket;
                }
            } else if (!(httpPacket instanceof HttpNull)) {  // 是请求/响应的后续(且已拼接完整) 可以发送
                return httpPacket;
            }
        }
        return new HttpNull();
    }

    /**
     * tcp包匹配<br>
     * 解析HTTP包前调用, 匹配请求/响应的后续(响应匹配请求 需要解析完再匹配)<br>
     * 主要处理后续包的拼接(第二个及之后的包)
     *
     * @param tcpPacket tcp包
     * @return null 未匹配成功 等待后续解析<br>
     * {@link HttpNull} 匹配失败或者不是完整包(已拼接本包数据) 无需处理<br>
     * {@link HttpRequest} 匹配为请求(并是完整包) 可以发送<br>
     * {@link HttpResponse} 匹配为响应(并是完整包) 可以发送<br>
     */
    private HttpPacket match(TcpPacket tcpPacket) {
        long time = System.currentTimeMillis();
        Iterator<HttpMessage> iterator = messages.iterator();
        while (iterator.hasNext()) {
            HttpMessage message = iterator.next();
            if (time - message.getTime() < timeout) {
                if (message.getHttpRequest() != null && Objects.equals(tcpPacket.getHeader().getAcknowledgmentNumberAsLong(), message.getHttpRequest().getAckNum())) {  // 是请求后续
                    packetAppend(message.getHttpRequest(), Unpooled.wrappedBuffer(tcpPacket.getPayload().getRawData()));  // 拼接请求 并判断完整
                    if (message.getHttpRequest().isComplete()) {
                        return message.getHttpRequest();  // 请求完整 发送
                    } else {
                        return new HttpNull();
                    }
                } else if (message.getHttpResponse() != null && Objects.equals(tcpPacket.getHeader().getAcknowledgmentNumberAsLong(), message.getHttpResponse().getAckNum())) {  // 是响应后续
                    packetAppend(message.getHttpResponse(), Unpooled.wrappedBuffer(tcpPacket.getPayload().getRawData()));  // 拼接响应 判断完整
                    if (message.getHttpResponse().isComplete()) {
                        iterator.remove();
                        return message.getHttpResponse();  // 响应完整 发送
                    } else {
                        return new HttpNull();
                    }
                }
            } else {
                iterator.remove();  // 超时缓存删除
            }
        }
        return null;
    }

    /**
     * 匹配请求/响应<br>
     * 调用{@link #match(TcpPacket)}之后, 若判断为第一个包, 进行解析, 解析后调用此方法<br>
     * 请求:<br>
     * 无论是否完整, 添加进缓存, 等待后续包在{@link #match(TcpPacket)}中处理<br>
     * 响应:<br>
     * 完整包: 清除请求的缓存并发送<br>
     * 不完整: 存入缓存等待后续包在{@link #match(TcpPacket)}中处理
     *
     * @param httpPacket 第一次请求/响应
     * @return 请求/响应
     */
    private HttpPacket match(HttpPacket httpPacket) {
        long time = System.currentTimeMillis();
        if (httpPacket instanceof HttpRequest) {  // 是起始请求
            httpPacket.setTimeId(httpPacket.getPacketTime().getTime());
            messages.addLast(new HttpMessage(time, (HttpRequest) httpPacket, null));  // 不管请求是否完整 都要缓存
            if (httpPacket.isComplete()) {
                return httpPacket;  // 请求完整 发送
            }
        } else if (httpPacket instanceof HttpResponse) {  // 是起始响应
            HttpResponse httpResponse = (HttpResponse) httpPacket;
            Iterator<HttpMessage> iterator = messages.iterator();
            while (iterator.hasNext()) {
                HttpMessage message = iterator.next();
                if (time - message.getTime() < timeout) {
                    if (message.getHttpRequest() != null && Objects.equals(httpResponse.getSeqNum(), message.getHttpRequest().getAckNum())) {  // 找到请求
                        httpResponse.setTimeId(message.getHttpRequest().getTimeId());  // 设置时间ID
                        if (httpResponse.isComplete()) {
                            iterator.remove();  // 响应完整 清除缓存
                            return httpResponse;  // 响应完整 发送
                        } else {
                            message.setHttpResponse(httpResponse);  // 响应不完整 存入缓存(因为是起始响应) 不发送
                        }
                    }
                }
            }
        }
        return new HttpNull();
    }

    /**
     * 解析HTTP状态行
     * 请求 POST /req/test?name=%E5%90%8D%E7%A7%B0&id=1,2,3&type=a&type=b HTTP/1.1
     * 响应 HTTP/1.1 200
     *
     * @param statusLine HTTP状态行
     * @return http包(HttpRequest 或 HttpResponse)
     */
    private HttpPacket readStatusLine(ByteBuf statusLine) {
        if (statusLine != null) {
            List<ByteBuf> split = split(statusLine, Unpooled.wrappedBuffer(new byte[]{' '}));

            if (split.size() == 3 && ByteBufUtil.equals(split.get(2), HTTP)) {
                // 是请求
                HttpRequest httpRequest = new HttpRequest();
                httpRequest.setHttpMethod(split.get(0).toString(StandardCharsets.UTF_8));
                List<ByteBuf> urlSplit = split(split.get(1), Unpooled.wrappedBuffer(new byte[]{'?'}), 2);
                httpRequest.setPath(urlSplit.get(0).toString(StandardCharsets.UTF_8));
                if (urlSplit.size() == 2) {
                    // 有问号 => 有参数
                    Map<String, Object> parameters = new HashMap<>();
                    for (ByteBuf keyEqValue : split(urlSplit.get(1), Unpooled.wrappedBuffer(new byte[]{'&'}))) {
                        List<ByteBuf> keyValueSplit = split(keyEqValue, Unpooled.wrappedBuffer(new byte[]{'='}), 2);
                        String key = urlDecode(keyValueSplit.get(0).toString(StandardCharsets.UTF_8));
                        if (keyValueSplit.size() == 2) {
                            for (ByteBuf value : split(keyValueSplit.get(1), Unpooled.wrappedBuffer(new byte[]{','}))) {
                                mapPut(parameters, key, urlDecode(value.toString(StandardCharsets.UTF_8)));
                            }
                        }
                    }
                    httpRequest.setParameters(parameters);
                }
                return httpRequest;
            } else if (split.size() >= 2 && ByteBufUtil.equals(split.get(0), (HTTP))) {
                // 是响应
                HttpResponse httpResponse = new HttpResponse();
                httpResponse.setResCode(Integer.parseInt(split.get(1).toString(StandardCharsets.UTF_8)));
                return httpResponse;
            }
        }
        return new HttpNull();
    }

    /**
     * URL解码
     *
     * @param url url的key或value
     * @return 解码内容
     */
    private String urlDecode(String url) {
        try {
            return URLDecoder.decode(url, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return url;
        }
    }

    /**
     * 解析HTTP首部行
     * 可能有多个key
     *
     * @param headerLines HTTP首部行
     * @return 1个key => value为String; 多个key => value为List
     */
    private Map<String, Object> readHeaderLines(List<ByteBuf> headerLines) {
        if (headerLines != null && headerLines.size() > 0) {
            Map<String, Object> headers = new HashMap<>();
            for (ByteBuf headerLine : headerLines) {
                List<ByteBuf> split = split(headerLine, Unpooled.wrappedBuffer(new byte[]{':', ' '}), 2);
                if (split.size() == 2) {
                    mapPut(headers, split.get(0).toString(StandardCharsets.UTF_8), split.get(1).toString(StandardCharsets.UTF_8));
                }
            }
            return headers;
        }
        return null;
    }

    /**
     * 调用map的put(k,v)方法 => 存如headers和parameters的map
     * 若同key存在多个value, 将value改为valueList
     *
     * @param map   map
     * @param key   k
     * @param value v
     */
    public void mapPut(Map<String, Object> map, String key, String value) {
        if (map.containsKey(key)) {
            if (map.get(key) instanceof List) {
                ((List) map.get(key)).add(value);
            } else {
                List<String> values = new ArrayList<>();
                values.add(String.valueOf(map.get(key)));
                values.add(value);
                map.put(key, values);
            }
        } else {
            map.put(key, value);
        }
    }

    /**
     * 将body内容拼接到请求或响应中<br>
     * 若完整包, {@link HttpPacket#complete} 为 true 不可再添加<br>
     *
     * @param packet httpPacket
     * @param append 拼接内容
     * @param <T>    {@link HttpRequest}/{@link HttpResponse}
     */
    private <T extends HttpPacket> void packetAppend(T packet, ByteBuf append) {
        if (checkTransferEncodingChunked(packet)) {  // Transfer-Encoding: chunked
            ByteBuf cacheBuf = (ByteBuf) packet.getHeaders().getOrDefault("Body-Cache", ByteBufAllocator.DEFAULT.buffer());
            cacheBuf = ByteBufAllocator.DEFAULT.compositeBuffer().addComponents(true, cacheBuf, append);
            while (cacheBuf.readableBytes() > 0) {
                int splitIndex = ByteBufUtil.indexOf(line1, cacheBuf);  // 第一个\r\n的位置
                int length = Integer.parseInt(cacheBuf.slice(0, splitIndex).toString(StandardCharsets.UTF_8), 0x10);
                if (length == 0) {  // 结束
                    packet.getHeaders().remove("Body-Cache");
                    ByteBuf dataBuf = (ByteBuf) packet.getHeaders().remove("Body-Data");
                    packet.setBody(dataBuf.toString(StandardCharsets.UTF_8));
                    ReferenceCountUtil.safeRelease(cacheBuf);
                    packet.setComplete(true);
                    return;
                } else if (cacheBuf.readableBytes() - splitIndex - line1.readableBytes() > length) {  // 第一个\r\n后的实际长度大于 第一段数据的应有长度
                    ByteBuf dataBuf = cacheBuf.slice(splitIndex + line1.readableBytes(), length);
                    cacheBuf = cacheBuf.slice(splitIndex + line1.readableBytes() * 2 + length,
                            cacheBuf.readableBytes() - splitIndex - line1.readableBytes() * 2 - length);
                    packet.getHeaders().put("Body-Cache", cacheBuf);
                    packet.getHeaders().put("Body-Data", packet.getHeaders().containsKey("Body-Data") ?
                            ByteBufAllocator.DEFAULT.compositeBuffer().addComponents(true, (ByteBuf) packet.getHeaders().get("Body-Data"), dataBuf) : dataBuf);
                } else {  // 第一个\r\n后的实际长度小于 第一段数据的应有长度 => 等待下一个包
                    packet.getHeaders().put("Body-Cache", cacheBuf);
                    break;
                }
            }
            return;
        }
        int length = checkContentLengthInt(packet);
        if (length > 0) {  // 是Content-Length类型
            ByteBuf dataBuf = (ByteBuf) packet.getHeaders().getOrDefault("Body", ByteBufAllocator.DEFAULT.buffer());
            dataBuf = ByteBufAllocator.DEFAULT.compositeBuffer().addComponents(true, dataBuf, append);
            if (dataBuf.readableBytes() < length) {
                packet.getHeaders().put("Body", dataBuf);
            } else {
                packet.setComplete(true);
                packet.setBody(dataBuf.toString(StandardCharsets.UTF_8));
                ReferenceCountUtil.safeRelease(dataBuf);
                packet.getHeaders().remove("Body");
            }
            return;
        }
        packet.setComplete(true); // 默认完整
    }

    /**
     * 切分ByteBuf<br>
     * String[] result = longData.split(shortData, count);<br>
     * List result = split(longData, shortData, count);
     *
     * @param longData  源Buf
     * @param shortData 切分Buf
     * @param count     切分数量
     * @return 切分
     */
    private List<ByteBuf> split(ByteBuf longData, ByteBuf shortData, int count) {
        int indexOf;
        List<ByteBuf> bufList = new ArrayList<>();
        while ((indexOf = ByteBufUtil.indexOf(shortData, longData)) != -1) {
            if (count != -1 && bufList.size() == count - 1) {
                break;
            }
            bufList.add(longData.slice(0, indexOf));
            longData = longData.slice(indexOf + shortData.readableBytes(), longData.readableBytes() - indexOf - shortData.readableBytes());
        }
        bufList.add(longData);
        return bufList;
    }

    /**
     * 切分ByteBuf<br>
     * String[] result = longData.split(shortData);<br>
     * List result = split(longData, shortData);
     *
     * @param longData  源Buf
     * @param shortData 切分Buf
     * @return 切分
     */
    private List<ByteBuf> split(ByteBuf longData, ByteBuf shortData) {
        return split(longData, shortData, -1);
    }

    /**
     * 检查是否是"Transfer-Encoding: Chunked"
     *
     * @param httpPacket http包
     * @return true 是chunked类型/false 不是chunked类型
     */
    private boolean checkTransferEncodingChunked(HttpPacket httpPacket) {
        if (httpPacket.getHeaders() != null && httpPacket.getHeaders().containsKey("Transfer-Encoding")) {
            Object obj = httpPacket.getHeaders().get("Transfer-Encoding");
            if (obj instanceof List) {
                for (Object value : (List) obj) {
                    if (value.equals("chunked")) {
                        return true;
                    }
                }
            } else {
                return obj.equals("chunked");
            }
        }
        return false;
    }

    /**
     * 检查是否是"Content-Length: [int]"
     *
     * @param httpPacket http包
     * @return 返回长度(小于0说明不是Content - Length类型)
     */
    private int checkContentLengthInt(HttpPacket httpPacket) {
        if (httpPacket.getHeaders() != null && httpPacket.getHeaders().containsKey("Content-Length")) {
            Object obj = httpPacket.getHeaders().get("Content-Length");
            if (obj instanceof List) {
                for (Object value : (List) obj) {
                    try {
                        int length = Integer.parseInt(String.valueOf(value));
                        if (length >= 0) {
                            return length;
                        }
                    } catch (NumberFormatException ignore) {
                        // 无法转换为数字不做处理 等待下一个
                    }
                }
            } else {
                try {
                    return Integer.parseInt(String.valueOf(obj));
                } catch (NumberFormatException ignore) {
                    // 无法转换为数字 说明不是Content-Length类型
                }
            }
        }
        return -1;
    }
}