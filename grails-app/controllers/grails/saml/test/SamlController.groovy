package grails.saml.test

import grails.converters.JSON

class SamlController {

    def springSecurityService
    def metadata

    def index(){
        render " index"
    }

    def success(){
        println "springSecurityService.principal.id = $springSecurityService.principal"
        render "success"

    }

    def idp(){
        println "params = $params"
        def allIdps = metadata.getIDPEntityNames()
        println "allIdps = $allIdps"
        def loginUrl = "${createLink(controller: 'login',action: 'auth', params: ['idp':allIdps[0]])}"
        println "loginUrl = $loginUrl"
        redirect (controller: 'login', action: 'auth', params: ['idp':allIdps[0]])
    }

    def logout(){
        render "logged out"
    }

    def login(){
        render "login"
    }
}
