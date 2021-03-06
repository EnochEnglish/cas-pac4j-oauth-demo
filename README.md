## What is this project?

This project *cas-pac4j-oauth-demo* has been created to test the OAuth/OpendID/CAS support in *CAS server version >= 4.0.0*. It's composed of two modules :

- the *cas-pac4j-oauth-client-demo* module is a CAS server which uses the OAuth/OpenID/CAS client mode : it acts as a client to delegate authentication to Facebook, Twitter... : [https://wiki.jasig.org/display/CASUM/OAuth+client+support+for+CAS+server+version+%3E%3D+4.0.0](https://wiki.jasig.org/display/CASUM/OAuth+client+support+for+CAS+server+version+%3E%3D+4.0.0)
- the *cas-pac4j-oauth-server-demo* module is a CAS server which uses the OAuth server mode : it plays the role of an OAuth server : [https://wiki.jasig.org/display/CASUM/OAuth+server+support](https://wiki.jasig.org/display/CASUM/OAuth+server+support).

## Quick start & test

To start quickly, build the project:

    mvn clean install

and start the two web applications with jetty:

    cd cas-pac4j-oauth-client-demo
    mvn jetty:run

    cd cas-pac4j-oauth-server-demo
    mvn -Djetty.port=8081 jetty:run

To test,

- call the [http://localhost:8080/cas](http://localhost:8080/cas) url and click on "Authenticate with ..." (on the CAS server configured in OAuth client mode)
- authenticate at your favorite provider (Facebook, Twitter...) or at the OAuth wrapped CAS server (same password as login, url : _http://localhost:8081/cas2_)
- be redirected to the first CAS server and successfully authenticated.

## Manual deployment

You can also deploy manually these two web applications in your favorite web applications server :

- cas-pac4j-oauth-client-demo on http://localhost:8080/cas
- cas-pac4j-oauth-server-demo on http://localhost:8081/cas2
