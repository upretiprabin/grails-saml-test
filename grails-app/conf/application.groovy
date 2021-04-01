// Added by the Spring Security Core plugin:
grails.plugin.springsecurity.userLookup.userDomainClassName = 'grails.saml.test.User'
grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'grails.saml.test.UserRole'
grails.plugin.springsecurity.authority.className = 'grails.saml.test.Role'
grails.plugin.springsecurity.rejectIfNoRule = true
grails.plugin.springsecurity.fii.rejectPublicInvocations = false
grails.plugin.springsecurity.useBasicAuth = true
grails.plugin.springsecurity.basic.realmName = 'Saml-test'
grails.plugin.springsecurity.securityConfigType = 'InterceptUrlMap'
grails.plugin.springsecurity.interceptUrlMap = [
        [pattern: '/',               access: ['permitAll']],

        [pattern: '/test/testAdmin',               access: ['ROLE_ADMIN']],
        [pattern: '/test/**',               access: ['ROLE_USER','ROLE_SAML']],
        [pattern: '/login/**',               access: ['permitAll']],
        [pattern: '/metadata/**',               access: ['permitAll']],
        [pattern: '/saml/**',               access: ['permitAll']],
        [pattern: '/error',          access: ['permitAll']],
        [pattern: '/index',          access: ['permitAll']],
        [pattern: '/index.gsp',      access: ['permitAll']],
        [pattern: '/shutdown',       access: ['permitAll']],
        [pattern: '/assets/**',      access: ['permitAll']],
        [pattern: '/**/js/**',       access: ['permitAll']],
        [pattern: '/**/css/**',      access: ['permitAll']],
        [pattern: '/**/images/**',   access: ['permitAll']],
        [pattern: '/**/favicon.ico', access: ['permitAll']]
]

grails.plugin.springsecurity.filterChain.chainMap = [
        [pattern: '/assets/**',      filters: 'none'],
        [pattern: '/**/js/**',       filters: 'none'],
        [pattern: '/**/css/**',      filters: 'none'],
        [pattern: '/**/images/**',   filters: 'none'],
        [pattern: '/**/favicon.ico', filters: 'none'],
        [pattern: '/**',             filters: 'JOINED_FILTERS']
]

grails.plugin.springsecurity.providerNames = ['samlAuthenticationProvider','daoAuthenticationProvider', 'anonymousAuthenticationProvider']

grails.plugin.springsecurity.saml.active = true
grails.plugin.springsecurity.saml.afterLoginUrl = '/saml/success'
grails.plugin.springsecurity.saml.afterLogoutUrl = '/saml/logout'
grails.plugin.springsecurity.saml.responseSkew = 300
grails.plugin.springsecurity.saml.useLocalRoles = true
grails.plugin.springsecurity.saml.signatureAlgorithm = 'rsa-sha256'
grails.plugin.springsecurity.saml.digestAlgorithm = 'sha256'
grails.plugin.springsecurity.saml.userGroupAttribute = 'roles'

grails.plugin.springsecurity.saml.autoCreate.active = false  //If you want the plugin to generate users in the DB as they are authenticated via SAML
grails.plugin.springsecurity.saml.autoCreate.key = 'id'
grails.plugin.springsecurity.saml.autoCreate.assignAuthorities=false  //If you want the plugin to assign the authorities that come from the SAML message.


grails.plugin.springsecurity.saml.metadata.defaultIdp = 'https://sts.windows.net/0c0a3fb0-88e0-46d7-b24b-67b12f8954d5/'
grails.plugin.springsecurity.saml.metadata.url = "security/pom-saml-test.xml"
grails.plugin.springsecurity.saml.metadata.url = '/saml/metadata'
grails.plugin.springsecurity.saml.metadata.providers = [myidp:'security/pom-saml-test.xml']
grails.plugin.springsecurity.saml.metadata.sp.file = "security/sp.xml"
grails.plugin.springsecurity.saml.metadata.sp.defaults.local = true;
grails.plugin.springsecurity.saml.metadata.sp.defaults.entityId = 'pom-saml'
grails.plugin.springsecurity.saml.metadata.sp.defaults.alias = 'pom-saml';
grails.plugin.springsecurity.saml.metadata.sp.defaults.securityProfile = 'pkix';
grails.plugin.springsecurity.saml.metadata.sp.defaults.signingKey = 'javaman';
grails.plugin.springsecurity.saml.metadata.sp.defaults.encryptionKey = 'javaman';
grails.plugin.springsecurity.saml.metadata.sp.defaults.tlsKey = 'javaman';
grails.plugin.springsecurity.saml.metadata.sp.defaults.requireArtifactResolveSigned = false;
grails.plugin.springsecurity.saml.metadata.sp.defaults.requireLogoutRequestSigned = false;
grails.plugin.springsecurity.saml.metadata.sp.defaults.requireLogoutResponseSigned = false;

grails.plugin.springsecurity.saml.keyManager.storeFile = "classpath:security/keystore.jks"
grails.plugin.springsecurity.saml.keyManager.storePass = 'changeit'
grails.plugin.springsecurity.saml.keyManager.passwords = [javaman:'changeit']
grails.plugin.springsecurity.saml.keyManager.defaultKey = 'javaman'

