package lt.bta.java2.sprngsecapi;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.ResponseEntity.ok;

@SpringBootApplication
public class SprngSecApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SprngSecApiApplication.class, args);
    }

}

@RestController
class Api {

    @RolesAllowed({"USER","ADMIN"})
    @GetMapping("/user")
    public Map method1() {
        return Collections.singletonMap("user", true);
    }

    @RolesAllowed("ADMIN")
    @GetMapping("/admin")
    public Map method2() {
        return Collections.singletonMap("admin", true);
    }

    @GetMapping("/any")
    public Map method3() {
        return Collections.singletonMap("any", true);
    }


    @Resource
    private AuthenticationManager authenticationManager;

    @Resource
    private JwtTokenProvider jwtTokenProvider;

    @PermitAll
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequest data) {
        // jei userio login duomenys neteisingi, tai bus ismetamas AuthenticationException
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(data.getUsername(), data.getPassword()));

        // jei useris sekmingai prisilogino, tai nustatome jo roles ir formuojame JWT tokena
        List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        String token = jwtTokenProvider.createToken(data.getUsername(), roles);
        Map<Object, Object> model = new HashMap<>();
        model.put("username", data.getUsername());
        model.put("token", token);
        return ok(model);
    }
}

@Data
class LoginRequest {
    private String username;
    private String password;
}

// Spring Security pagrindinis konfiguravimo komponentas:
// Reikia aprasyti 2 bean'us: UserDetailsService ir AuthenticationManager
// o taip pat configure metode nurodyti saugumo parametrus bei papildoma musu filtra JwtTokenFilter
@EnableGlobalMethodSecurity(jsr250Enabled = true)
@Configuration
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private JwtTokenFilter jwtTokenFilter;

    // Pati primityviausia UserDetailsService implementacija skirta tik demo uzdaviniams!!!
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        List<UserDetails> users = Arrays.asList(
                User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build(),
                User.withDefaultPasswordEncoder().username("admin").password("admin").roles("ADMIN").build()
        );
        return new InMemoryUserDetailsManager(users);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated()

                .and()
                .csrf().disable()
                .formLogin().disable()

                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
        ;
    }
}

// Spring boot security filtras - skirtas patikrinti JWT tokena
@Component
class JwtTokenFilter extends OncePerRequestFilter {

    @Resource
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = jwtTokenProvider.resolveToken(request);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            Authentication auth = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }
}

