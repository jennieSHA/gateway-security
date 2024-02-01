package com.security.gatewayservice.filter;

import com.security.gatewayservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {
    @Autowired
    private JwtUtil jwtUtil;


    @Autowired
    private RouteValidator routeValidator;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("***************::IN THE AuthenticationFilter");
        System.out.println("***************::IN THE AuthenticationFilter HEADERS"+ exchange.getRequest().getHeaders());
        if( routeValidator.isSecured.test(exchange.getRequest())){
            if(exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
            {
                System.out.println("***************::missing Authentication HEADERS");
//                throw  new RuntimeException("missing Authentication Header");
            }

            String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            if(authHeader != null && authHeader.startsWith("BEARER "))
            {
                authHeader = authHeader.substring(7);
            }
            try{
                jwtUtil.isTokenExpired(authHeader);
            }
            catch(Exception e)
            {
                System.out.println("invalid access...!");
                throw new RuntimeException("unauthorized access to application");
            }
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
