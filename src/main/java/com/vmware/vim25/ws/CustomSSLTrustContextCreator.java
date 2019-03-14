package com.vmware.vim25.ws;

import javax.net.ssl.*;
import java.rmi.RemoteException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicBoolean;

public class CustomSSLTrustContextCreator {

    static SSLContext getTrustContext(TrustManager trustManager) throws RemoteException {
        SSLContext sslContext;
        try {

            TrustManager[] trustManagers = new TrustManager[] { trustManager };
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
        }catch(NoSuchAlgorithmException e) {
            throw new RemoteException("Unable to find suitable algorithm while attempting to communicate with remote server.", e);
        } catch(KeyManagementException e) {
            throw new RemoteException("An error occurred initializing SSL context due to a problem with key management.", e);
        }

        return sslContext;
    }
}
