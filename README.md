# spring-jwt-secured-apps [![CI](https://github.com/daggerok/spring-jwt-secured-apps/workflows/CI/badge.svg)](https://github.com/daggerok/spring-jwt-secured-apps/actions?query=workflow%3ACI)
From zero to JWT hero...

## Table of Content
* [Step 0: No security](#step-0)
* [Step 1: Spring Security defaults](#step-1)
* [Step 2: Using custom WebSecurityConfigurerAdapter, UserDetailsService](#step-2)
* [Step 3: Simple JWT integration](#step-3)
* [Step 4: Teach Spring auth with JWT from request headers](#step-4)
* [Versioning and releasing](#maven)
* [Resources and used links](#resources)

## step: 0

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
    const headers = { 'Content-Type': 'application/json' };

    let options = { method: 'GET', headers, };
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

## step: 1

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

## step: 2

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

## step: 3

first, let's add required dependencies:

```xml
  <dependencies>
    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt</artifactId>
    </dependency>
  </dependencies>
```

### update backend

implement auth rest resources:

```java
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
```

where:

_JwtService_

```java
@Service
class JwtService {
  String generateToken(UserDetails userDetails) {
    /* Skipped jwt infrastructure logic... See sources for details */
  }
}
```

_AuthenticationManager_

```java
class MyWebSecurity extends WebSecurityConfigurerAdapter {
  
  @Override
  @Bean // Requires to being able to inject AuthenticationManager bean in our AuthResource.
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

  // ...
}
```

### update frontend

```js
  options = {
    method: 'POST', headers,
    body: JSON.stringify({ username: 'dag', password: 'dag' }),
  };

  fetch('/api/auth', options)
    .catch(errorHandler)
    .then(response => response.json())
    .then(json => {
      console.log('auth json', json);
      const result = JSON.stringify(json);
      const textNode = document.createTextNode(result);
      document.querySelector('#app').prepend(textNode);
    })
  ;

  function errorHandler(reason) {
    console.log(reason);
  }
```

### test

with that, open http://127.0.0.1:8080 page, or use username and password, which must be the same and must contain
`max` or `dag` words in your _AuthenticationRequest_:

```bash
http post :8080/api/auth username=dag password=dag
```

## step: 4

let's now implement request filter interceptor, which is going to
parse authorization header for Bearer token and authorizing spring
security context accordingly to its validity:

_JwtRequestFilter_

```java
@Component
@RequiredArgsConstructor
class JwtRequestFilter extends OncePerRequestFilter {

  final JwtService jwtService;
  final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                  HttpServletResponse httpServletResponse,
                                  FilterChain filterChain) throws ServletException, IOException {

    var prefix = "Bearer ";
    var authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

    Optional.ofNullable(authorizationHeader).ifPresent(ah -> {

      var parts = ah.split(prefix);
      if (parts.length < 2) return;

      var accessToken = parts[1].trim();
      Optional.of(accessToken). filter(Predicate.not(String::isBlank)).ifPresent(at -> {

        if (jwtService.isTokenExpire(at)) return;

        var username = jwtService.extractUsername(at);
        var userDetails = userDetailsService.loadUserByUsername(username);
        if (!jwtService.validateToken(at, userDetails)) return;

        var authentication = new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
        var details = new WebAuthenticationDetailsSource().buildDetails(httpServletRequest);

        authentication.setDetails(details);
        SecurityContextHolder.getContext().setAuthentication(authentication);
      });
    });

    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }
}
```

finally, update fronted to leverage localStorage as
accessToken store:

```js
function headersWithAuth() {
  const accessToken = localStorage.getItem('accessToken');
  return !accessToken ? headers : Object.assign({}, headers,
    { Authorization: 'Bearer ' + accessToken });
}

function auth() {
  const options = {
    method: 'POST', headers: headersWithAuth(),
    body: JSON.stringify({ username: 'max', password: 'max' }),
  };
  fetch('/api/auth', options)
    .then(response => response.json())
    .then(json => {
      if (json.accessToken) localStorage.setItem('accessToken', json.accessToken);
    })
  ;
}

function api() {
  const options = { method: 'GET', headers: headersWithAuth() };
  fetch('/api/hello', options)
    .then(response => response.json())
    .then(json => {
      if (json.status && json.status >= 400) {
        auth();
        return;
      }
      const result = JSON.stringify(json);
      const textNode = document.createTextNode(result);
      const div = document.createElement('div');
      div.append(textNode)
      document.querySelector('#app').prepend(div);
    })
  ;
}

auth();
setInterval(api, 1111);
```

with that, we can verify on http://127.0.0.1:8080 page
how frontend applications is automatically doing
authentication and accessing rest api!

## maven

we will be releasing after each important step! so it will be easy simply checkout needed version from git tag.

increment version:

```bash
1.1.1?->1.1.2
./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set -DgenerateBackupPoms=false -DnewVersion=\${parsedVersion.majorVersion}.\${parsedVersion.minorVersion}.\${parsedVersion.nextIncrementalVersion}
```

current release version:

```bash
# 1.2.3-SNAPSHOT -> 1.2.3
./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set -DgenerateBackupPoms=false -DnewVersion=\${parsedVersion.majorVersion}.\${parsedVersion.minorVersion}.\${parsedVersion.incrementalVersion}
```

next snapshot version:

```bash
# 1.2.3? -> 1.2.4-SNAPSHOT
./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set -DgenerateBackupPoms=false -DnewVersion=\${parsedVersion.majorVersion}.\${parsedVersion.minorVersion}.\${parsedVersion.nextIncrementalVersion}-SNAPSHOT
```

release version without maven-release-plugin (when you aren't using *-SNAPSHOT version for development):

```bash
currentVersion=`./mvnw -q --non-recursive exec:exec -Dexec.executable=echo -Dexec.args='${project.version}'`
git tag "v$currentVersion"

./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set -DgenerateBackupPoms=false \
  -DnewVersion=\${parsedVersion.majorVersion}.\${parsedVersion.minorVersion}.\${parsedVersion.nextIncrementalVersion}
nextVersion=`./mvnw -q --non-recursive exec:exec -Dexec.executable=echo -Dexec.args='${project.version}'`

git add . ; git commit -am "v$currentVersion release." ; git push --tags
```

release version using maven-release-plugin (when you are using *-SNAPSHOT version for development):

```bash
currentVersion=`./mvnw -q --non-recursive exec:exec -Dexec.executable=echo -Dexec.args='${project.version}'`
./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set \
    -DnewVersion=\${parsedVersion.majorVersion}.\${parsedVersion.minorVersion}.\${parsedVersion.nextIncrementalVersion}
developmentVersion=`./mvnw -q --non-recursive exec:exec -Dexec.executable=echo -Dexec.args='${project.version}'`
./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set -DnewVersion="$currentVersion"
./mvnw clean release:prepare release:perform \
    -DreleaseVersion="$currentVersion" -DdevelopmentVersion="$developmentVersion" \
    -B -DgenerateReleasePoms=false
```

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
