# spring-jwt-secured-apps [![CI](https://github.com/daggerok/spring-jwt-secured-apps/workflows/CI/badge.svg)](https://github.com/daggerok/spring-jwt-secured-apps/actions?query=workflow%3ACI)
From zero to JWT hero...

## Table of Content
* [Step 0: No security](#step-0-no-security)
* [Step 1: Spring Security defaults](#step-1-spring-security-defaults)
* [Step 2: Using custom WebSecurityConfigurerAdapter, UserDetailsService](#step-2-simple-spring-configurer)
* [TBD](#to-be-continue)
* [Resources and used links](#resources)

## step-0-no-security

let's use simple spring boot web app with `pom.xml` file:

```xml
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
```

with `SpringJwtSecuredAppsApplication.java` file:

```java
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
```

with `src/main/resources/static/index.html` file:

```html
<!doctype html>
<html lang="en">
<head>
  <title>JWT</title>
</head>
<body>
<h1>Hello</h1>
<ul id="app"></ul>
<script>
  document.addEventListener('DOMContentLoaded', onDOMContentLoaded, false);

  function onDOMContentLoaded() {
    const options = {
      method: 'GET',
      headers: { 'Conten-Type': 'application/json' },
    };
    fetch('/api/hello', options)
      .then(response => response.json())
      .then(json => {
        console.log('json', json);
        const textNode = document.createTextNode(JSON.stringify(json));
        document.querySelector('#app').prepend(textNode);
      })
    ;
  }
</script>
</body>
</html>
```

with that we can query with no security at all:

```bash
http :8080
http :8080/api/hello
```

## step-1-spring-security-defaults

let's use default spring-security:

```xml
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
  </dependencies>
```

user has generated password (initially taken from server logs), so let's configure it in `application.properties` file:

```properties
spring.security.user.password=80427fb5-888f-4669-83c0-893ca655a82e
```

with that we can query like so:

```bash
http -a user:80427fb5-888f-4669-83c0-893ca655a82e :8080
http -a user:80427fb5-888f-4669-83c0-893ca655a82e :8080/api/hello
```

## step-2-simple-spring-configurer

create custom security config:

```java
@Configuration
@RequiredArgsConstructor
class MyWebSecurity extends WebSecurityConfigurerAdapter {

  final MyUserDetailsService myUserDetailsService;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(myUserDetailsService);
  }
}
```

where `UserDetailsService` implemented as follows:

```java
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
```

also, we need `PasswordEncoder` in context:

```java
@Configuration
class MyPasswordEncoderConfig {

  @Bean
  PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
```

with that, we can use username and password, which must be the same and must contain `max` or `dag` words:

```bash
http -a max:max get :8080
http -a daggerok:daggerok get :8080/api/hello
```

## to be continue...

## resources

* [Official Apache Maven documentation](https://maven.apache.org/guides/index.html)
* [Spring Boot Maven Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/2.3.0.M4/maven-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/2.3.0.M4/maven-plugin/reference/html/#build-image)
* [Spring Security](https://docs.spring.io/spring-boot/docs/2.2.6.RELEASE/reference/htmlsingle/#boot-features-security)
* [Spring Configuration Processor](https://docs.spring.io/spring-boot/docs/2.2.6.RELEASE/reference/htmlsingle/#configuration-metadata-annotation-processor)
* [Spring Web](https://docs.spring.io/spring-boot/docs/2.2.6.RELEASE/reference/htmlsingle/#boot-features-developing-web-applications)
* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Authenticating a User with LDAP](https://spring.io/guides/gs/authenticating-ldap/)
* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/bookmarks/)
* https://www.youtube.com/watch?v=X80nJ5T7YpE
