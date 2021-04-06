package grails.saml.test

class SamlController {

    def springSecurityService

    def index(){
        render " index"
    }

    def success(){
        println "springSecurityService.principal.id = $springSecurityService.principal"
        redirect(url: "http://127.0.0.1:3001/app/dashboard")

    }

    def logout(){
        render "logged out"
    }

    def login(){
        render "login"
    }
}
