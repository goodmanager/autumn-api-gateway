package com.autumn.gateway.filter;

import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.autumn.common.config.SecurityConfig;
import com.autumn.common.constant.ErrorCodeException;
import com.autumn.common.constant.JwtClaimsKey;
import com.autumn.common.exception.ApplicationException;
import com.autumn.common.util.DateUtil;
import com.autumn.common.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 用户认证
 */
@Component
public class AuthCheckGlobalFilter implements GlobalFilter, Ordered {

	@Autowired
	private SecurityConfig securityConfig;

	@Override
	public int getOrder() {
		return -200;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();
		String requestPath = request.getPath().value();
		if (securityConfig.getExcludedSignAndTokenUrl().contains(requestPath)
			|| securityConfig.getExcludedTokenUrl().contains(requestPath)
			|| securityConfig.getExcludeExtraUrl().contains(requestPath)) {
			return chain.filter(exchange);
		} else {
			return checkAuth(exchange, chain);
		}
	}

	/**
	 * access token验证
	 *
	 * @param exchange
	 * @param chain
	 * @return
	 */
	private Mono<Void> checkAuth(ServerWebExchange exchange, GatewayFilterChain chain) {
		HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
		String accessToken = httpHeaders.getFirst(JwtClaimsKey.X_ACCESSTOKEN.getKey());
		Map<String, String> jwtConfig = securityConfig.getJwt();
		DecodedJWT claimMap = JwtUtil.verifyJwtToken(jwtConfig.get("secretKey"), accessToken);
		//解析 jwt token失败
		if (claimMap == null) {
			throw new ApplicationException(ErrorCodeException.ERROR_TOKEN.getErrorCode(),
				HttpStatus.UNAUTHORIZED.value(),
				ErrorCodeException.ERROR_TOKEN.getMessage());
		} else {
			String uid = claimMap.getClaim(JwtClaimsKey.X_Uid.getKey()).asString();
			String appId = claimMap.getClaim(JwtClaimsKey.X_AppId.getKey()).asString();
			if (uid.equalsIgnoreCase(httpHeaders.getFirst(JwtClaimsKey.X_Uid.getKey()))
				&& appId.equalsIgnoreCase(httpHeaders.getFirst(JwtClaimsKey.X_AppId.getKey()))) {
				return chain.filter(exchange);
			} else if (LocalDateTime.now().isAfter(DateUtil.toLocalDateTime(claimMap.getClaim(PublicClaims.EXPIRES_AT).asDate()))) {
				// token 过期
				throw new ApplicationException(ErrorCodeException.EXPIRED_TOKEN.getErrorCode(),
					HttpStatus.UNAUTHORIZED.value(),
					ErrorCodeException.EXPIRED_TOKEN.getMessage());
			} else {
				// 错误的token
				throw new ApplicationException(
					ErrorCodeException.ERROR_TOKEN.getErrorCode(), HttpStatus.UNAUTHORIZED.value(),
					ErrorCodeException.ERROR_TOKEN.getMessage());
			}
		}
	}
}
