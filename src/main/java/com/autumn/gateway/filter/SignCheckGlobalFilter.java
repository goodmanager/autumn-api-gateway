package com.autumn.gateway.filter;

import com.autumn.common.config.SecurityConfig;
import com.autumn.common.constant.ErrorCodeException;
import com.autumn.common.constant.HashType;
import com.autumn.common.exception.ApplicationException;
import com.autumn.common.util.HashUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 *
 */
@Component
public class SignCheckGlobalFilter implements GlobalFilter, Ordered {

	@Autowired
	private SecurityConfig securityConfig;

	@Override
	public int getOrder() {
		return -100;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();
		String requestPath = request.getPath().value();
		if (securityConfig.getExcludedSignAndTokenUrl().contains(requestPath)
			|| securityConfig.getExcludeExtraUrl().contains(requestPath)) {
			return chain.filter(exchange);
		} else {
			return checkSign(exchange, chain);
		}
	}

	/**
	 * 检验签名
	 *
	 * @param exchange
	 * @param chain
	 * @return
	 */
	private Mono<Void> checkSign(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();
		// 调用者传来的签名
		String sign = request.getHeaders().getFirst("sign");
		// 调用者传来的时间戳
		long timestamp = Long.valueOf(request.getHeaders().getFirst("timestamp"));
		if (System.currentTimeMillis() - timestamp > securityConfig.getRequestExpired()) {
			throw new ApplicationException(ErrorCodeException.EXPIRED_REQUEST.getErrorCode(), 400,
				ErrorCodeException.EXPIRED_REQUEST.getMessage());
		}
		String serverSign = "";
		HttpMethod httpMethod = request.getMethod();
		if (httpMethod.name().equals(HttpMethod.GET.name())) {
			serverSign = createSign(exchange);
		} else if (httpMethod.name().equals(HttpMethod.POST.name())) {
			serverSign = createSign(exchange);
		} else if (httpMethod.name().equals(HttpMethod.OPTIONS.name())) {
			return chain.filter(exchange);
		} else {
			throw new ApplicationException(ErrorCodeException.FAIL_HTTP_METHOD.getErrorCode(), 405,
				ErrorCodeException.FAIL_HTTP_METHOD.getMessage());
		}
		if (serverSign.equalsIgnoreCase(sign)) {
			return chain.filter(exchange);
		} else {
			throw new ApplicationException(ErrorCodeException.FAIL_SIGN_CHECK.getErrorCode(), 400,
				ErrorCodeException.FAIL_SIGN_CHECK.getMessage());
		}
	}

	/**
	 * 创建服务器端签名
	 *
	 * @param exchange
	 * @return
	 */
	private String createSign(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();
		String appId = request.getHeaders().getFirst("appId");
		String timestamp = request.getHeaders().getFirst("timestamp");
		// 请求的 requestURI
		String requestUrl = request.getPath().value();
		String methodValue = request.getMethodValue();
		StringBuffer stringBuffer = new StringBuffer();
		if (methodValue.equalsIgnoreCase(HttpMethod.GET.name())) {
			// get方法请求时的参数组装
			MultiValueMap<String, String> queryParams = request.getQueryParams();
			List<String> collect = queryParams.keySet().stream().sorted().collect(Collectors.toList());
			for (String key : collect) {
				stringBuffer.append("&" + key + "=" + queryParams.getFirst(key));
			}
		} else {
			// post方法时的参数组装
			MediaType contentType = request.getHeaders().getContentType();
			if (contentType == MediaType.APPLICATION_FORM_URLENCODED) {
				Mono<MultiValueMap<String, String>> formData = exchange.getFormData();
				formData.subscribe((obj) -> {
					Iterator<String> iterator = obj.keySet().stream().sorted().iterator();
					while (iterator.hasNext()) {
						String next = iterator.next();
						stringBuffer.append("&" + next + "=" + obj.getFirst(next));
					}
				});
			} else {
				stringBuffer.append("&");
				Flux<DataBuffer> body = request.getBody();
				body.subscribe((obj) -> {
					stringBuffer.append(obj.toString(StandardCharsets.UTF_8));
				});
			}
		}
		String signParam = "appId=" + appId + requestUrl + stringBuffer.deleteCharAt(0).toString() + "timestamp=" +
			timestamp;
		return HashUtil.encrypt(signParam, securityConfig.getAppSecret(), HashType.SHA256);
	}
}
