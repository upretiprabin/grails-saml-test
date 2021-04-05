import grails.plugin.springsecurity.SpringSecurityUtils
import grails.saml.test.CustomSpringSamlUserDetailsService
import grails.saml.test.UserPasswordEncoderListener
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter

// Place your Spring DSL code here
beans = {
    userPasswordEncoderListener(UserPasswordEncoderListener)

    userDetailsService(CustomSpringSamlUserDetailsService){
        authorityClassName = SpringSecurityUtils.securityConfig.authority.className
        authorityJoinClassName = SpringSecurityUtils.securityConfig.userLookup.authorityJoinClassName
        authorityNameField = SpringSecurityUtils.securityConfig.authority.nameField
        samlAutoCreateActive = SpringSecurityUtils.securityConfig.saml.autoCreate.active
        samlAutoAssignAuthorities = SpringSecurityUtils.securityConfig.saml.autoCreate.assignAuthorities as Boolean
        samlAutoCreateKey = SpringSecurityUtils.securityConfig.saml.autoCreate.key as String
        samlUserAttributeMappings = SpringSecurityUtils.securityConfig.saml.userAttributeMappings
        samlUserGroupAttribute = SpringSecurityUtils.securityConfig.saml.userGroupAttribute as String
        samlUserGroupToRoleMapping = SpringSecurityUtils.securityConfig.saml.userGroupToRoleMapping
        userDomainClassName = SpringSecurityUtils.securityConfig.userLookup.userDomainClassName
        samlUseLocalRoles = SpringSecurityUtils.securityConfig.saml.useLocalRoles
        grailsApplication = ref('grailsApplication')
    }

    statelessSecurityContextRepository(NullSecurityContextRepository)
    securityContextPersistenceFilter(SecurityContextPersistenceFilter, ref('statelessSecurityContextRepository'))


}
