------------------
keytab entries:
------------------
http://java.sun.com/j2se/1.4.2/docs/guide/security/SecurityToolsSummary.html

C:\Code\Sun\Java\j2sdk1.4.2_16\bin>klist -k FILE:D:/workspaces/workspace_oscar/1_gss_kerb/src/main/resources/keys/cmxd5014.keytab
C:\Code\Sun\Java\j2sdk1.4.2_16\bin>klist -k -t -K -e FILE:D:/workspaces/workspace_oscar/1_gss_kerb/src/main/resources/keys/cmxd5014.keytab			// list détaillé
C:\Code\Sun\Java\j2sdk1.4.2_16\bin>ktab -a toto pwd -k FILE:D:/workspaces/workspace_oscar/1_gss_kerb/src/main/resources/keys/cmxd5014.keytab		// ajout
C:\Code\Sun\Java\j2sdk1.4.2_16\bin>ktab -d toto -k FILE:D:/workspaces/workspace_oscar/1_gss_kerb/src/main/resources/keys/cmxd5014.keytab			// suppression
C:\Code\Sun\Java\j2sdk1.4.2_16\bin>ktab -l -k FILE:D:/workspaces/workspace_oscar/1_gss_kerb/src/main/resources/keys/cmxd5014.keytab					// list
------------------

---------------------------
Launching GSSCredentialTest:
---------------------------
java 
-Djava.security.krb5.realm=<REALM> 
-Djava.security.krb5.kdc=<KDC> 
-Djavax.security.auth.useSubjectCredsOnly=false 
-Djava.security.auth.login.config=D:\workspaces\workspace_oscar\1_gss_kerb\src\main\resources\ServerLogin.conf 
GSSCredentialTest

ex:
java 
-Djava.security.krb5.realm=CM.PAR.EMEA.CIB 
-Djava.security.krb5.kdc=CM.PAR.EMEA.CIB 
-Djavax.security.auth.useSubjectCredsOnly=false 
-Djava.security.auth.login.config=D:\workspaces\workspace_oscar\1_gss_kerb\src\main\resources\ServerLogin.conf 
GSSCredentialTest
---------------------------

---------------------------
Launching SampleServer:
---------------------------
java 
-Djava.security.krb5.realm=<REALM> 
-Djava.security.krb5.kdc=<KDC> 
-Djavax.security.auth.useSubjectCredsOnly=false 
-Djava.security.auth.login.config=D:\workspaces\workspace_oscar\1_gss_kerb\src\main\resources\ServerLogin.conf 
SampleServer <port_number>

ex:
java 
-Djava.security.krb5.realm=CM.PAR.EMEA.CIB 
-Djava.security.krb5.kdc=CM.PAR.EMEA.CIB 
-Djavax.security.auth.useSubjectCredsOnly=false 
-Djava.security.auth.login.config=D:\workspaces\workspace_oscar\1_gss_kerb\src\main\resources\ServerLogin.conf 
SampleServer 54321
---------------------------

---------------------------
Launching SampleClient:
---------------------------
java 
-Djava.security.krb5.realm=<REALM> 
-Djava.security.krb5.kdc=<KDC> 
-Djavax.security.auth.useSubjectCredsOnly=false 
-Djava.security.auth.login.config=D:\workspaces\workspace_oscar\1_gss_kerb\src\main\resources\ClientLogin.conf 
SampleClient <service_principal> <host> <port_number>

ex:
java 
-Djava.security.krb5.realm=CM.PAR.EMEA.CIB 
-Djava.security.krb5.kdc=CM.PAR.EMEA.CIB 
-Djavax.security.auth.useSubjectCredsOnly=false 
-Djava.security.auth.login.config=D:\workspaces\workspace_oscar\1_gss_kerb\src\main\resources\ClientLogin.conf 
SampleClient HTTP/cmxd5014.dev.cm.par.emea.cib localhost 54321
---------------------------
