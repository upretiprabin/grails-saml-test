package grails.saml.test

class SamlController {

    def index(){
        render " index"
    }

    def SSO() {
        render "SSO"
    }

    def success(){
        render "success"
    }

    def logout(){
        render "logged out"
    }

    def login(){
        render "login"
    }
}
