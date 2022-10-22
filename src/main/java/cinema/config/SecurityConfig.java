package cinema.config;

import cinema.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    public SecurityConfig(PasswordEncoder passwordEncoder,
                          UserDetailsServiceImpl userDetailsServiceImpl) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsServiceImpl = userDetailsServiceImpl;
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsServiceImpl).passwordEncoder(passwordEncoder);
    }

    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/register").permitAll()
                .antMatchers(HttpMethod.GET, "/cinema-halls/**").hasAnyAuthority("ADMIN","USER")
                .antMatchers(HttpMethod.POST, "/cinema-halls/**").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.GET,"/movies/**").hasAnyAuthority("ADMIN","USER")
                .antMatchers(HttpMethod.POST,"/movies/**").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.GET,"/movie-sessions/available").hasAnyAuthority("ADMIN",
                        "USER")
                .antMatchers(HttpMethod.POST,"/movie-sessions/**").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.PUT,"/movie-sessions/{id}").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.DELETE,"/movie-sessions/{id}").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.GET,"/orders").hasAuthority("USER")
                .antMatchers(HttpMethod.POST,"/orders/complete").hasAuthority("USER")
                .antMatchers(HttpMethod.PUT,"/shopping-carts/movie-sessions").hasAuthority("USER")
                .antMatchers(HttpMethod.GET,"/shopping-carts/by-user").hasAuthority("USER")
                .antMatchers(HttpMethod.GET,"/users/by-email").hasAuthority("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .httpBasic()
                .and()
                .csrf().disable();
    }
}
