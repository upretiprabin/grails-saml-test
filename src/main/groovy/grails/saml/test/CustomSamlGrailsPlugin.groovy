package grails.saml.test

import grails.plugins.*
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition
import org.grails.plugin.springsecurity.saml.CustomSAMLBootstrap
import org.grails.plugin.springsecurity.saml.GrailsSAMLAuthenticationProvider
import org.grails.plugin.springsecurity.saml.MetadataDisplayFilterUTF8
import org.grails.plugin.springsecurity.saml.SamlSecurityService
import org.grails.plugin.springsecurity.saml.SamlTagLib
import org.grails.plugin.springsecurity.saml.SpringSamlUserDetailsService
import org.jdom.Document
import org.jdom.input.SAXBuilder
import org.jdom.output.XMLOutputter
import org.jdom.output.Format
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.springframework.core.io.ClassPathResource;
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler
import org.springframework.security.saml.SAMLDiscovery
import org.springframework.security.saml.storage.EmptyStorageFactory
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.saml.SAMLEntryPoint
import org.springframework.security.saml.SAMLProcessingFilter
import org.springframework.security.saml.SAMLLogoutFilter
import org.springframework.security.saml.SAMLLogoutProcessingFilter
import org.springframework.security.saml.websso.WebSSOProfileOptions
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
import org.springframework.security.saml.websso.WebSSOProfileImpl
import org.springframework.security.saml.websso.WebSSOProfileECPImpl
import org.springframework.security.saml.websso.SingleLogoutProfileImpl
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl
import org.springframework.security.saml.processor.HTTPPostBinding
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding
import org.springframework.security.saml.processor.HTTPArtifactBinding
import org.springframework.security.saml.processor.HTTPSOAP11Binding
import org.springframework.security.saml.processor.HTTPPAOS11Binding
import org.springframework.security.saml.processor.SAMLProcessorImpl
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate
import org.springframework.security.saml.metadata.MetadataDisplayFilter
import org.springframework.security.saml.metadata.MetadataGenerator
import org.springframework.security.saml.metadata.CachingMetadataManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider
import org.opensaml.xml.parse.BasicParserPool
import org.apache.commons.httpclient.HttpClient

class CustomSamlGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    String grailsVersion = '3.3.0 > *'
    String author = 'Jeff Wilson'
    String authorEmail = 'jeffwilson70@gmail.com'
    String title = 'Spring Security Saml2 Plugin'
    String description = 'Grails 3 Saml2 Support for Spring Security plugin.'
    String documentation = 'https://jeffwils.github.io/grails-spring-security-saml/'
    String license = 'APACHE'
    //def organization = [name: 'Grails', url: 'http://www.grails.org/']
    def organization = [:]
    def issueManagement = [url: 'https://github.com/jeffwils/grails-spring-security-saml/issues']
    def scm = [url: 'https://github.com/jeffwils/grails-spring-security-saml']
    def profiles = ['web']

    def dependsOn = ['springSecurityCore' : '3.2.0 > *']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
            'test/**',
            "grails-app/views/error.gsp",
            "UrlMappings",
            'docs/**',
            'scripts/PublishGithub.groovy'
    ]

    // Any additional developers beyond the author specified above.
    def developers = [[ name: "Alvaro Sanchez-Mariscal", email: "alvaro.sanchez@salenda.es" ], [ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ],[ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ], [ name: "Jeff Beck", email: "beckje01@gmail.com" ], [ name: "Sphoorti Acharya", email: "sphoortiacharya@gmail.com" ]]


    List<MetadataProvider> providers = []

    Closure doWithSpring() {
        {->
            def conf = SpringSecurityUtils.securityConfig
            if( !isActive( conf ) )
                return

            println 'Configuring Custom Spring Security SAML ...'

            //Due to Spring DSL limitations, need to import these beans as XML definitions
            def beansFile = "classpath:security/springSecuritySamlBeans.xml"
            println "Importing beans from ${beansFile}..."
            delegate.importBeans beansFile

            xmlns context:"http://www.springframework.org/schema/context"
            context.'annotation-config'()
            context.'component-scan'('base-package': "org.springframework.security.saml")

            def idpPath = conf.saml.entryPoint.idpSelectionPath
            samlIDPDiscovery(SAMLDiscovery){
                idpSelectionPath = idpPath
            }

            SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'
            SpringSecurityUtils.registerLogoutHandler 'logoutHandler'
            SpringSecurityUtils.registerFilter 'samlEntryPoint', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 1
            SpringSecurityUtils.registerFilter 'metadataFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 2
            SpringSecurityUtils.registerFilter 'samlProcessingFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 3
            SpringSecurityUtils.registerFilter 'samlLogoutFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 4
            SpringSecurityUtils.registerFilter 'samlLogoutProcessingFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 5
            SpringSecurityUtils.registerFilter 'samlIDPDiscovery', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 6

            successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
                alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
                defaultTargetUrl = conf.saml.afterLoginUrl
            }

            logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
                defaultTargetUrl = conf.saml.afterLogoutUrl
            }

            SAMLLogger(SAMLDefaultLogger)

            if(!getResource(conf.saml.keyManager.storeFile).exists()) {
                throw new IOException("Keystore cannot be loaded from file '${conf.saml.keyManager.storeFile}'. " +
                        "Please check that the path configured in " +
                        "'grails.plugin.springsecurity.saml.keyManager.storeFile' in your application.yml is correct.")
            }

            keyManager(JKSKeyManager,
                    conf.saml.keyManager.storeFile, conf.saml.keyManager.storePass, conf.saml.keyManager.passwords, conf.saml.keyManager.defaultKey)

            samlEntryPoint(SAMLEntryPoint) {
                filterProcessesUrl = conf.auth.loginFormUrl 						// '/saml/login'
//                if (idpSelectionPath) {
//                    idpSelectionPath = idpPath 					// '/index.gsp'
//                }
                samlDiscovery = ref('samlIDPDiscovery')
                defaultProfileOptions = ref('webProfileOptions')
            }

            webProfileOptions(WebSSOProfileOptions) {
                includeScoping = false
            }

            metadataFilter(MetadataDisplayFilterUTF8) {
                filterProcessesUrl = conf.saml.metadata.url 						// '/saml/metadata'
            }

            metadataGenerator(MetadataGenerator)

            // TODO: Update to handle any type of meta data providers for default to file based instead http provider.
            log.debug "Dynamically defining bean metadata providers... "
            def providerBeanName = "extendedMetadataDelegate"
            conf.saml.metadata.providers.each {k,v ->

                println "Registering metadata key: ${k} and value: $v"
                "${providerBeanName}"(ExtendedMetadataDelegate) { extMetaDataDelegateBean ->

                    metadataTrustCheck = false
                    metadataRequireSignature = false

                    if(v.startsWith("https:") || v.startsWith("http:")) {
                        def timeout = conf.saml.metadata.timeout
                        def url = v
                        httpMetadataProvider(HTTPMetadataProvider, url, timeout) { bean ->
                            parserPool = ref('parserPool')
                        }
                        extMetaDataDelegateBean.constructorArgs = [ref('httpMetadataProvider'), new ExtendedMetadata()]
                    } else {
                        filesystemMetadataProvider(FilesystemMetadataProvider) { bean ->
                            if (v.startsWith("/") || v.indexOf(':') == 1) {
                                File resource = new File(v)
                                bean.constructorArgs = [resource]
                            } else {
                                def resource = new ClassPathResource(v)
                                if(!resource.exists()) {
                                    throw new IOException("Identity provider metadata cannot be loaded from file '${v}'. " +
                                            "Please check that the path configured in " +
                                            "'grails.plugin.springsecurity.saml.providers.${k}' in your application.yml is correct.")
                                }
                                try {
                                    bean.constructorArgs = [resource.getFile()]
                                } catch (FileNotFoundException fe) {
                                    final InputStream is = resource.getInputStream();
                                    try {
                                        final InputStreamReader reader = new InputStreamReader(is);
                                        try {
                                            final Document headerDoc = new SAXBuilder().build(reader);
                                            XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
                                            String xmlString = outputter.outputString(headerDoc);
                                            File temp = File.createTempFile("idp-local",".xml");
                                            BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
                                            bw.write(xmlString);
                                            bw.close();
                                            bean.constructorArgs = [temp]
                                            temp.deleteOnExit();
                                        } finally {
                                            reader.close();
                                        }
                                    } finally {
                                        is.close();
                                    }
                                }
                            }
                            parserPool = ref('parserPool')
                        }

                        extMetaDataDelegateBean.constructorArgs = [ref('filesystemMetadataProvider'), new ExtendedMetadata()]
                    }
                }

                providers << ref(providerBeanName)
            }

            // you can only define a single service provider configuration
            def spFile = conf.saml.metadata.sp.file
            def defaultSpConfig = conf.saml.metadata.sp.defaults
            if (spFile) {
                println "Loading the service provider metadata from ${spFile}..."
                spMetadata(ExtendedMetadataDelegate) { spMetadataBean ->
                    spMetadataProvider(FilesystemMetadataProvider) { spMetadataProviderBean ->
                        if (spFile.startsWith("/") || spFile.indexOf(':') == 1) {
                            File spResource = new File(spFile)
                            spMetadataProviderBean.constructorArgs = [spResource]
                        }else{
                            def spResource = new ClassPathResource(spFile)
                            if(!spResource.exists()) {
                                throw new IOException("Service provider metadata cannot be loaded from file '${spFile}'. " +
                                        "Please check that the path configured in " +
                                        "'grails.plugin.springsecurity.saml.metadata.sp.file' in your application.yml is correct.")
                            }
                            try{
                                spMetadataProviderBean.constructorArgs = [spResource.getFile()]
                            } catch(FileNotFoundException fe){
                                final InputStream is = spResource.getInputStream();
                                try {
                                    final InputStreamReader reader = new InputStreamReader(is);
                                    try {
                                        final Document headerDoc = new SAXBuilder().build(reader);
                                        XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
                                        String xmlString = outputter.outputString(headerDoc);
                                        File temp = File.createTempFile("sp-local",".xml");
                                        BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
                                        bw.write(xmlString);
                                        bw.close();
                                        spMetadataProviderBean.constructorArgs = [temp]
                                        temp.deleteOnExit();
                                    } finally {
                                        reader.close();
                                    }
                                } finally {
                                    is.close();
                                }
                            }
                        }

                        parserPool = ref('parserPool')
                    }

                    //TODO consider adding idp discovery default
                    spMetadataDefaults(ExtendedMetadata) { extMetadata ->
                        local = defaultSpConfig."local"
                        alias = defaultSpConfig."alias"
                        securityProfile = defaultSpConfig."securityProfile"
                        signingKey = defaultSpConfig."signingKey"
                        encryptionKey = defaultSpConfig."encryptionKey"
                        tlsKey = defaultSpConfig."tlsKey"
                        requireArtifactResolveSigned = defaultSpConfig."requireArtifactResolveSigned"
                        requireLogoutRequestSigned = defaultSpConfig."requireLogoutRequestSigned"
                        requireLogoutResponseSigned = defaultSpConfig."requireLogoutResponseSigned"
                        idpDiscoveryEnabled = defaultSpConfig."idpDiscoveryEnabled"
                    }

                    spMetadataBean.constructorArgs = [ref('spMetadataProvider'), ref('spMetadataDefaults')]
                }

                providers << ref('spMetadata')
            }

            metadata(CachingMetadataManager,providers) { metadataBean ->
                // At this point, due to Spring DSL limitations, only one provider
                // can be defined so just picking the first one
//                metadataBean.constructorArgs = [providers]
//                providers = providers

                if (defaultSpConfig?."entityId") {
                    hostedSPName = defaultSpConfig?."entityId"
                } else {
                    if (defaultSpConfig?."alias") {
                        hostedSPName = defaultSpConfig?."alias"
                    }
                }
                if(conf.saml.metadata?.defaultIdp != '') {
                    defaultIDP = conf.saml.metadata?.defaultIdp
                }
            }


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
                grailsApplication = grailsApplication
            }

            samlAuthenticationProvider(GrailsSAMLAuthenticationProvider) {
                userDetails = ref('userDetailsService')
                hokConsumer = ref('webSSOprofileConsumer')
            }

            contextProvider(SAMLContextProviderImpl){
                storageFactory = new EmptyStorageFactory()
            }

            webSSOprofileConsumer(WebSSOProfileConsumerImpl){
                maxAuthenticationAge = 86400
                responseSkew = conf.saml.responseSkew
            }

            samlProcessingFilter(SAMLProcessingFilter) {
                authenticationManager = ref('authenticationManager')
                authenticationSuccessHandler = ref('successRedirectHandler')
                sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                authenticationFailureHandler = ref('authenticationFailureHandler')
            }

            authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
                redirectStrategy = ref('redirectStrategy')
                defaultFailureUrl = conf.saml.loginFailUrl ?: '/login/authfail?login_error=1'
                useForward = conf.failureHandler.useForward // false
                ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
                exceptionMappings = conf.failureHandler.exceptionMappings // [:]
            }

            redirectStrategy(DefaultRedirectStrategy) {
                contextRelative = conf.redirectStrategy.contextRelative // false
            }

            sessionFixationProtectionStrategy(SessionFixationProtectionStrategy)

            logoutHandler(SecurityContextLogoutHandler) {
                invalidateHttpSession = true
            }

            samlLogoutFilter(SAMLLogoutFilter,
                    ref('logoutSuccessHandler'), ref('logoutHandler'), ref('logoutHandler'))

            samlLogoutProcessingFilter(SAMLLogoutProcessingFilter,
                    ref('logoutSuccessHandler'), ref('logoutHandler'))

            webSSOprofile(WebSSOProfileImpl)

            ecpprofile(WebSSOProfileECPImpl)

            logoutprofile(SingleLogoutProfileImpl)

            postBinding(HTTPPostBinding, ref('parserPool'), ref('velocityEngine'))

            redirectBinding(HTTPRedirectDeflateBinding, ref('parserPool'))

            artifactBinding(HTTPArtifactBinding,
                    ref('parserPool'),
                    ref('velocityEngine'),
                    ref('artifactResolutionProfile')
            )

            artifactResolutionProfile(ArtifactResolutionProfileImpl, ref('httpClient')) {
                processor = ref('soapProcessor')
            }

            httpClient(HttpClient)

            soapProcessor(SAMLProcessorImpl, ref('soapBinding'))

            soapBinding(HTTPSOAP11Binding, ref('parserPool'))

            paosBinding(HTTPPAOS11Binding, ref('parserPool'))

            bootStrap(CustomSAMLBootstrap)

            velocityEngine(VelocityFactory) { bean ->
                bean.factoryMethod = "getEngine"
            }

            parserPool(BasicParserPool)

            securityTagLib(SamlTagLib) {
                springSecurityService = ref('springSecurityService')
                webExpressionHandler = ref('webExpressionHandler')
                webInvocationPrivilegeEvaluator = ref('webInvocationPrivilegeEvaluator')
            }

            springSecurityService(SamlSecurityService) {
                config = conf
                authenticationTrustResolver = ref('authenticationTrustResolver')
                grailsApplication = grailsApplication //(GrailsApplication)ref('grailsApplication')
                passwordEncoder = ref('passwordEncoder')
                objectDefinitionSource = ref('objectDefinitionSource')
                userDetailsService = ref('userDetailsService')
                userCache = ref('userCache')
            }

            //https://github.com/jeffwils/grails-spring-security-saml/issues/63
            //remove beans from SecurityFilterAutoConfiguration.java
            //by overriding them with an empty string
            springSecurityFilterChain(String, "")
            securityFilterChainRegistration(String, "")

            println '...finished configuring Spring Security SAML'
        }

    }

    void doWithDynamicMethods() {
        // TODO Implement registering dynamic methods to classes (optional)
    }

    void doWithApplicationContext() {
        // TODO Implement post initialization spring config (optional)
    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }

    private static boolean isActive( def conf ) {
        final PLUGIN_NOT_AVAILABLE = 'SAML plugin will not be available'
        if( !conf ) {
            // This is unlikely to ever occur due to default configs included in plugins,
            // but historically has always been checked, so keeping.
            println "There is no Spring Security config, $PLUGIN_NOT_AVAILABLE."

            return false
        }
        else if( !conf.active ) {
            println "Spring Security Core plugin is not active, $PLUGIN_NOT_AVAILABLE."

            return false
        }
        else if( conf.saml.active || !conf.saml.custom.active ) {
            println "saml.active is not true, $PLUGIN_NOT_AVAILABLE."

            return false
        }

        true
    }
}
