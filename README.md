# spring-jwt-secured-apps [![CI](https://github.com/daggerok/spring-jwt-secured-apps/workflows/CI/badge.svg)](https://github.com/daggerok/spring-jwt-secured-apps/actions?query=workflow%3ACI)
From zero to JWT hero...

## Table of Content
* [Step 0: No security](#step-0-no-security)
* [Maven: versioning and releasing](#versioning-and-releasing)
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

## to be continue...

## versioning and releasing

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

./mvnw build-helper:parse-version -DgenerateBackupPoms=false versions:set -DgenerateBackupPoms=false -DnewVersion=\${parsedVersion.majorVersion}.\${parsedVersion.minorVersion}.\${parsedVersion.nextIncrementalVersion}
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
