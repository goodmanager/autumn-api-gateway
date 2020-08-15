package com.autumn.gateway.exception;

import com.autumn.common.constant.ErrorCodeException;
import com.autumn.common.exception.ApplicationException;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.view.ViewResolver;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GatewayExceptionHandler implements ErrorWebExceptionHandler {

	private List<HttpMessageReader<?>> messageReaders = Collections.emptyList();

	private List<HttpMessageWriter<?>> messageWriters = Collections.emptyList();

	private List<ViewResolver> viewResolvers = Collections.emptyList();

	private ThreadLocal<Map<String, Object>> exceptionHandlerResult = new ThreadLocal<>();

	public void setMessageReaders(List<HttpMessageReader<?>> messageReaders) {
		Assert.notNull(messageReaders, "'messageReaders' must not be null");
		this.messageReaders = messageReaders;
	}

	public void setViewResolvers(List<ViewResolver> viewResolvers) {
		this.viewResolvers = viewResolvers;
	}

	public void setMessageWriters(List<HttpMessageWriter<?>> messageWriters) {
		Assert.notNull(messageWriters, "'messageWriters' must not be null");
		this.messageWriters = messageWriters;
	}

	@Override
	public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
		Map<String, Object> errorMap = formatMessage(ex);
		if (exchange.getResponse().isCommitted()) {
			return Mono.error(ex);
		}
		exceptionHandlerResult.set(errorMap);
		ServerRequest newRequest = ServerRequest.create(exchange, this.messageReaders);
		return RouterFunctions.route(RequestPredicates.all(), this::renderErrorResponse).route(newRequest)
			.switchIfEmpty(Mono.error(ex)).flatMap((handler) -> handler.handle(newRequest))
			.flatMap((response) -> write(exchange, response));
	}

	private Map<String, Object> formatMessage(Throwable ex) {
		Map<String, Object> exceptionResult = new HashMap<>();
		exceptionResult.put("errorCode", ErrorCodeException.FAILED.getErrorCode());
		if (ex instanceof NotFoundException) {
			String reason = ((NotFoundException) ex).getReason();
			exceptionResult.put("message", reason);
		} else if (ex instanceof ResponseStatusException) {
			ResponseStatusException responseStatusException = (ResponseStatusException) ex;
			exceptionResult.put("message", responseStatusException.getMessage());
		} else if (ex instanceof ApplicationException) {
			ApplicationException applicationException = (ApplicationException) ex;
			int code = applicationException.getErrorCode();
			String message = applicationException.getMessage();
			if (null != applicationException.getObjects()) {
				message = String.format(message, applicationException.getObjects());
			}
			exceptionResult.put("message", message);
			exceptionResult.put("errorCode", code);
		} else {
			exceptionResult.put("message", ex.getMessage());
		}
		return exceptionResult;
	}

	private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
		Map<String, Object> result = exceptionHandlerResult.get();
		return ServerResponse.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON)
			.body(BodyInserters.fromValue(result));
	}

	private Mono<? extends Void> write(ServerWebExchange exchange, ServerResponse response) {
		exchange.getResponse().getHeaders().setContentType(response.headers().getContentType());
		return response.writeTo(exchange, new ResponseContext());
	}

	private class ResponseContext implements ServerResponse.Context {

		@Override
		public List<HttpMessageWriter<?>> messageWriters() {
			return GatewayExceptionHandler.this.messageWriters;
		}

		@Override
		public List<ViewResolver> viewResolvers() {
			return GatewayExceptionHandler.this.viewResolvers;
		}
	}

}
