package daggerok;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

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

  @PostMapping("/api/hello")
  Map<String, String> post() {
    return Map.of("Hello", "world");
  }
}

@Service
class JwtService {

  @Value("jwt.signingKey:very-secret")
  String signingKey;

  boolean validateToken(String token, UserDetails userDetails) {
    var isNotExpire = !isTokenExpire(token);
    var username = Objects.requireNonNull(userDetails).getUsername();
    var isUsernameValid = username.equals(extractUsername(token));
    return isNotExpire && isUsernameValid;
  }

  String generateToken(UserDetails userDetails) {
    var claims = new ConcurrentHashMap(Map.of("ololo", "trololo"));
    return createToken(claims, userDetails.getUsername());
  }

  /* private api */

  private String createToken(Map<String, Object> claims, String subject) {
    var now = Instant.now();
    return Jwts.builder()
               .setClaims(claims)
               .setSubject(subject)
               .setIssuedAt(new Date(now.toEpochMilli()))
               .setExpiration(new Date(now.plus(24, ChronoUnit.HOURS)
                                          .toEpochMilli()))
               .signWith(SignatureAlgorithm.HS256, signingKey)
               .compact();
  }

  private String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  private boolean isTokenExpire(String token) {
    return extractExpiration(token).before(new Date(Instant.now().toEpochMilli()));
  }

  private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    var claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts.parser()
               .setSigningKey(signingKey)
               .parseClaimsJws(token)
               .getBody();
  }
}

@Data
@NoArgsConstructor
class AuthenticationRequest {
  private String username, password;
}

@lombok.Value
class AuthenticationResponse {
  String accessToken;
}

@RestController
@RequiredArgsConstructor
class JwtResource {

  final JwtService jwtService;
  final UserDetailsService userDetailsService;
  final AuthenticationManager authenticationManager;

  @PostMapping("/api/auth")
  AuthenticationResponse authenticate(@RequestBody AuthenticationRequest request) {
    var token = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
    var authentication = authenticationManager.authenticate(token);
    var userDetails = userDetailsService.loadUserByUsername(request.getUsername());
    var jwtToken = jwtService.generateToken(userDetails);
    return new AuthenticationResponse(jwtToken);
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

@Configuration
@RequiredArgsConstructor
class MyWebSecurity extends WebSecurityConfigurerAdapter {

  final MyUserDetailsService myUserDetailsService;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(myUserDetailsService);
  }

  /**
   * Requires to being able to inject AuthenticationManager bean in our AuthResource.
   */
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  /**
   * Requires to:
   * - post authentication without CSRF protection
   * - permit all requests for index page and /api/auth auth resource path
   */
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
          .mvcMatchers(HttpMethod.GET, "/").permitAll()
          .mvcMatchers(HttpMethod.POST, "/api/auth").permitAll()
          .anyRequest().fullyAuthenticated()//.authenticated()//
        .and()
          .csrf().disable()
        // .formLogin()
    ;
  }
}

@SpringBootApplication
public class SpringJwtSecuredAppsApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringJwtSecuredAppsApplication.class, args);
  }
}
