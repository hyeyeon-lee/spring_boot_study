package com.hyeyeon.study.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	private final UserService userService;

	public PasswordEncoder PasswordEncoder() {
		return new BCryptPasswordEncoder(); // 비밀번호 암호화
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/login", "/sineup", "/user").permitAll() // 누구나 접근 허용
				.antMatchers("/").hasRole("USER") // USER, ADMIN만 접근 가능
				.antMatchers("/admin").hasRole("ADMIN") // ADMIN만 접근 가능
				.anyRequest().authenticated() // 나머지 요청들은 권한의 종류완 상관없지만 권한이 있어야 함
				.and().formLogin().loginPage("/login") // 로그인 페이지 링크
				.defaultSuccessUrl("/") // 로그인 후 리다이렉트 주소
				.and().logout().logoutSuccessUrl("/login") // 로그아웃 성공시 리다이렉트 주소
				.invalidateHttpSession(true) // 로그아웃 후 세션 삭제
		;
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/css/**", "/js/**", "/img/**"); // 기본 접근 가능 인증 무시
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService).passwordEncoder(PasswordEncoder());
	}

}
