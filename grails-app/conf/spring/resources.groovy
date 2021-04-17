import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.saml.test.CustomSamlGrailsPlugin
import grails.saml.test.CustomSpringSamlUserDetailsService
import grails.saml.test.UserPasswordEncoderListener
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.storage.EmptyStorageFactory
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter

// Place your Spring DSL code here
beans = {
    userPasswordEncoderListener(UserPasswordEncoderListener)

    statelessSecurityContextRepository(NullSecurityContextRepository)
    securityContextPersistenceFilter(SecurityContextPersistenceFilter, ref('statelessSecurityContextRepository'))

    springSecuritySamlGrailsPlugin(CustomSamlGrailsPlugin)

}
