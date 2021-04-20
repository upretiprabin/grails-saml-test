package grails.saml.test

import grails.gorm.transactions.Transactional

@Transactional
class TestService {

    def loadData() {

        def adminRole = new Role(authority: 'ROLE_ADMIN').save()
        def userRole = new Role(authority: 'ROLE_USER').save()
        def samlRole = new Role(authority: 'ROLE_SAML').save()
        samlRole.save()
        def testUser = new User(username: 'admin_prabin', password: 'admin').save()
        def testUser1 = new User(username: 'user_prabin', password: 'user').save()

        UserRole.create testUser, adminRole
        UserRole.create testUser1, userRole
        UserRole.withSession {
            it.flush()
            it.clear()
        }
        println "User.count() = ${User.count()}"
        println "Role.count() = ${Role.count()}"
    }
}
