package net.unicon.authn.jaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;

/**
 * @author Jj!
 */
public class NotAsSimpleLoginModule implements LoginModule {
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;

    private boolean succeeded = false;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
    }

    public boolean login() throws LoginException {
        NameCallback nameCallback = new NameCallback("name:");
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        try {
            callbackHandler.handle(new Callback[]{nameCallback, passwordCallback});
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnsupportedCallbackException e) {
            e.printStackTrace();
        }

        if (nameCallback.getName().equals(new String(passwordCallback.getPassword()))) {
            this.succeeded = true;
            return true;
        }
        this.succeeded = false;
        return false;
    }

    public boolean commit() throws LoginException {
        if (this.succeeded) {
            // Add sample principal
            final List<IdPAttributeValue<?>> idpAttrVals = new LinkedList<IdPAttributeValue<?>>();
            final IdPAttributeValue idpAttrVal = new StringAttributeValue("1");
            idpAttrVals.add(idpAttrVal);
            final IdPAttribute idpAttribute = new IdPAttribute("uid");
            idpAttribute.setValues(idpAttrVals);
            final IdPAttributePrincipal idpPrincipal = new IdPAttributePrincipal(idpAttribute);
            this.subject.getPrincipals().add(idpPrincipal);
        }
        return this.succeeded;
    }

    public boolean abort() throws LoginException {
        return this.logout();
    }

    public boolean logout() throws LoginException {
        subject.getPrincipals().clear();
        this.succeeded = false;
        return true;
    }
}
