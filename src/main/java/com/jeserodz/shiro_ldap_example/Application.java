package com.jeserodz.shiro_ldap_example;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class Application {

    private static final transient Logger log = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        log.info("Hello World");

        // Step 1: BootStrap shiro into you application
        Factory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = (SecurityManager) factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // Step 2: Login
        Subject user = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("Jese Rodriguez", "jeser123");
        try {
            user.login(token);
        } 
        catch (AuthenticationException ae) {
            log.error(ae.toString()) ;
            return ;
        }
        log.info("User [" + user.getPrincipal() + "] logged in successfully.");
        

        // Step 3: Check if the user has permission
        if (user.isPermitted("File:write:xyz.doc")) {
            log.info(user.getPrincipal() + " has permission to write xyz.doc ");
        } else {
            log.info(user.getPrincipal() + " does not have permission to write xyz.doc ");
        }
        if (user.isPermitted("File:read:xyz.doc")) {
            log.info(user.getPrincipal() + " has permission to read xyz.doc ");
        } else {
            log.info(user.getPrincipal() + " does not have permission to read xyz.doc ");
        }
        
        // Step 4: Session data
        Session session = user.getSession();
        session.setAttribute( "someKey", "aValue" );
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("Retrieved the correct value from session! [" + value + "]");
        }
        
        // Step 5: Logout
        user.logout();
        log.info("logged out.");
    }
}
