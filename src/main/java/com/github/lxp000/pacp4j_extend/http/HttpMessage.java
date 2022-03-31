package com.github.lxp000.pacp4j_extend.http;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class HttpMessage {
    private Long time;
    private HttpRequest httpRequest;
    private HttpResponse httpResponse;
}
