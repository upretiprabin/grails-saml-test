package grails.saml.test

class TestController {
    def springSecurityService
    def index() {
        println "springSecurityService.principal.id = $springSecurityService.principal"
        render "at index"
    }

    def testAdmin(){
        println "springSecurityService.principal.id = $springSecurityService.principal"

        render "at test admin"
    }

    def testUser(){
        println "springSecurityService.principal.id = $springSecurityService.principal"

        render "at test user"
    }

    def logout(){
        session.invalidate()
        render "logged out"
    }
}
