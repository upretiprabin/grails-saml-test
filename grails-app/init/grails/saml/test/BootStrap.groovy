package grails.saml.test

class BootStrap {

    def testService

    def init = { servletContext ->
        testService.loadData()
    }
    def destroy = {
    }
}
