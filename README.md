# Getting Started

### Reference Documentation
For further reference, please consider the following sections:

* [Official Gradle documentation](https://docs.gradle.org)

### Guides
The following guides illustrate how to use some features concretely:

* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/bookmarks/)
* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Authenticating a User with LDAP](https://spring.io/guides/gs/authenticating-ldap/)

### Additional Links
These additional references should also help you:

* [Gradle Build Scans – insights for your project's build](https://scans.gradle.com#gradle)


### Kas gali būti svarbu

- __Klasėje _SecurityConfig_ aprašyti _AuthenticationManager_ tipo _@Bean_.__ 

    Jis bus naudojamas realizuojant __Api__ klasėje metodą __login__. 
    
- __Klasėje _SecurityConfig_ aprašyti _UserDetailsService_ tipo _@Bean_.__ 
  
    Jis bus naudojamas kaip "netikrų" sistemos userių šaltinis. 
          
- __Sukurti komponentą _JwtTokenProvider_.__

    Jis bus naudojamas security filtre __JwtTokenFilter__ ir taip pat __Api__ klasės __login__ metode.

- __Klasės _SecurityConfig_ metode _configure_ uždraudžiame naudoti http sesijas.__
    ```
    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    ```

- __Klasės _SecurityConfig_ metode _configure_ užregistruoti filtrą _JwtTokenProvider_.__
    ```
    .addFilterBefore(new JwtTokenFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
    ```

### Naudingi linkai 

* [Protect REST APIs with Spring Security and JWT](https://medium.com/@hantsy/protect-rest-apis-with-spring-security-and-jwt-5fbc90305cc5)
* [A Custom Filter in the Spring Security Filter Chain](https://www.baeldung.com/spring-security-custom-filter)
