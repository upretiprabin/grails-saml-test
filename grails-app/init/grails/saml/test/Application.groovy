package grails.saml.test

import grails.boot.GrailsApp
import grails.boot.config.GrailsAutoConfiguration

import groovy.transform.CompileStatic
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration

@CompileStatic
@EnableAutoConfiguration(exclude = [SecurityFilterAutoConfiguration])
class Application extends GrailsAutoConfiguration {
    static void main(String[] args) {
        GrailsApp.run(Application, args)
    }
}