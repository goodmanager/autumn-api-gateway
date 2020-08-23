package com.autumn.gateway.filter;

import com.autumn.common.config.SecurityConfig;
import com.autumn.common.constant.HashType;
import com.autumn.common.util.HashUtil;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.CachedBodyOutputMessage;
import org.springframework.cloud.gateway.support.BodyInserterContext;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ReactiveHttpOutputMessage;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

@Component
public class ResponseSignGlobalFilter implements GlobalFilter, Ordered {

	private static final Logger logger = LoggerFactory.getLogger(ResponseSignGlobalFilter.class);

	@Autowired
	private SecurityConfig securityConfig;

	@Autowired
	private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

	@Override
	public int getOrder() {
		return NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1;
	}

	/**
	 * ResponseEncrypt api返回值,是否加密或签名,0:直接返回(默认) 1:返回值签名,签名放在头部
	 *
	 * @param exchange
	 * @param chain
	 * @return
	 */
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();
		String requestPath = request.getPath().value();
		int responseEncrypt = 0;
		if (!StringUtils.isEmpty(request.getHeaders().getFirst("ResponseEncrypt"))) {
			responseEncrypt = Integer.valueOf(request.getHeaders().getFirst("ResponseEncrypt"));
		}
		if (securityConfig.getExcludedSignAndTokenUrl().contains(requestPath)
			|| securityConfig.getExcludeExtraUrl().contains(requestPath)
			|| responseEncrypt == 0) {
			return chain.filter(exchange);
		} else {
			return processResponse(responseEncrypt, exchange, chain);
		}
	}

	private Mono<Void> processResponse(int responseEncrypt, ServerWebExchange exchange, GatewayFilterChain chain) {

		if (responseEncrypt == 0) {
			return chain.filter(exchange);
		} else {
			ServerHttpResponseDecorator responseDecorator = new ServerHttpResponseDecorator(exchange.getResponse()) {
				@Override
				public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {

					ServerHttpResponse originalResponse = exchange.getResponse();
					DataBufferFactory bufferFactory = originalResponse.bufferFactory();
					BodyInserter<DataBufferFactory, ReactiveHttpOutputMessage> bodyInserter = BodyInserters
						.fromValue(bufferFactory);
					CachedBodyOutputMessage outputMessage = new CachedBodyOutputMessage(exchange,
						exchange.getResponse().getHeaders());

					return bodyInserter.insert(outputMessage, new BodyInserterContext()).then(Mono.defer(() -> {
						Flux<DataBuffer> flux = rebuildResponseBody(exchange, outputMessage,
							getDelegate());
						HttpHeaders headers = getDelegate().getHeaders();
						if (!headers.containsKey(HttpHeaders.TRANSFER_ENCODING)) {
							flux = flux.doOnNext((data) -> {
								headers.setContentLength(data.readableByteCount());
							});
						}
						flux = flux.doOnNext(data -> {
							headers.set("sign", data.toString(StandardCharsets.UTF_8));
						});
						return getDelegate().writeWith(flux);
					}));
				}
			};

			return chain.filter(exchange.mutate().response(responseDecorator).build());
		}
	}

	private Flux<DataBuffer> rebuildResponseBody(ServerWebExchange exchange,
	                                             CachedBodyOutputMessage outputMessage, ServerHttpResponse delegate) {
		Flux<DataBuffer> messageBody = outputMessage.getBody();
		return messageBody.map(buffer -> {
			CharBuffer charBuffer = StandardCharsets.UTF_8.decode(buffer.asByteBuffer());
			DataBufferUtils.release(buffer);
			//具体的服务返回的内容
			String text = charBuffer.toString();

			ServerHttpRequest request = exchange.getRequest();
			String timestamp = request.getHeaders().getFirst("timestamp");
			String sign = HashUtil.encrypt("timestamp=" + timestamp + text,
				securityConfig.getAppSecret(), HashType.SHA256);
			return delegate.bufferFactory()
				.wrap(sign.getBytes(StandardCharsets.UTF_8));
		});
	}
}
