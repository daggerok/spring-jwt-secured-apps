package daggerok;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

@Controller
class IndexPage {

  @GetMapping("")
  String index() {
    return "index.html";
  }
}

@RestController
class HelloResource {

  @GetMapping("/api/hello")
  Map<String, String> hello() {
    return Map.of("Hello", "world");
  }
}

@Configuration
class MyPasswordEncoderConfig {

  @Bean
  PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}

@Service
@RequiredArgsConstructor
class MyUserDetailsService implements UserDetailsService {

  final PasswordEncoder passwordEncoder;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return Optional.ofNullable(username)
                   .filter(u -> u.contains("max") || u.contains("dag"))
                   .map(u -> new User(username,
                                      passwordEncoder.encode(username),
                                      AuthorityUtils.createAuthorityList("USER")))
                   .orElseThrow(() -> new UsernameNotFoundException(String.format("User %s not found.", username)));
  }
}

// @Configuration
@EnableWebSecurity
@RequiredArgsConstructor
class MyWebSecurity extends WebSecurityConfigurerAdapter {

  final MyUserDetailsService myUserDetailsService;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(myUserDetailsService);
  }
}

@SpringBootApplication
public class SpringJwtSecuredAppsApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringJwtSecuredAppsApplication.class, args);
  }
}
