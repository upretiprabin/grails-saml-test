package grails.saml.test

class SamlController {

    def springSecurityService

    def index(){
        render " index"
    }

    def success(){
        println "springSecurityService.principal.id = $springSecurityService.principal"
        println "here at success"
        render "success"
    }

    def logout(){
        render "logged out"
    }

    def login(){
        render "login"
    }
}
