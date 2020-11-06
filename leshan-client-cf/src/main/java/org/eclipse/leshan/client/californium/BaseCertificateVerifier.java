/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.client.californium;

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.x509.AdvancedCertificateVerifier;
import org.eclipse.leshan.core.util.X509CertUtil;

public abstract class BaseCertificateVerifier implements AdvancedCertificateVerifier {

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    @Override
    public void verifyCertificate(CertificateMessage message, DTLSSession session) throws HandshakeException {
        verifyCertificate(null, false, message, session);
    }

    /**
     * Ensure that chain is not empty
     */
    protected void validateCertificateChainNotEmpty(CertPath certChain, InetSocketAddress foreignPeerAddress)
            throws HandshakeException {
        if (certChain.getCertificates().size() == 0) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
                    foreignPeerAddress);
            throw new HandshakeException("Certificate chain could not be validated : server cert chain is empty",
                    alert);
        }
    }

    /**
     * Ensure that received certificate is x509 certificate
     */
    protected X509Certificate validateReceivedCertificateIsSupported(CertPath certChain,
            InetSocketAddress foreignPeerAddress) throws HandshakeException {
        Certificate receivedServerCertificate = certChain.getCertificates().get(0);
        if (!(receivedServerCertificate instanceof X509Certificate)) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE,
                    foreignPeerAddress);
            throw new HandshakeException("Certificate chain could not be validated - unknown certificate type", alert);
        }
        return (X509Certificate) receivedServerCertificate;
    }

    protected void validateSubject(final DTLSSession session, final X509Certificate receivedServerCertificate)
            throws HandshakeException {
        final InetSocketAddress peerSocket = session.getPeer();

        if (X509CertUtil.matchSubjectDnsName(receivedServerCertificate, peerSocket.getHostName()))
            return;

        if (X509CertUtil.matchSubjectInetAddress(receivedServerCertificate, peerSocket.getAddress()))
            return;

        AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE, session.getPeer());
        throw new HandshakeException(
                "Certificate chain could not be validated - server identity does not match certificate", alert);
    }

    protected CertPath expandCertPath(CertPath certPath, X509Certificate[] trustedCertificates) {
        if (trustedCertificates == null)
            return certPath;

        List<? extends Certificate> certificates = certPath.getCertificates();
        boolean modified = false;

        if (certificates.size() == 0) {
            return certPath;
        }

        try {
            ArrayList<X509Certificate> chain = new ArrayList<>();

            for (Certificate cert : certificates) {
                if (cert instanceof X509Certificate) {
                    chain.add((X509Certificate) cert);
                } else {
                    return certPath;
                }
            }

            // Max depth guard against chain loop.
            int maxDepth = 32;

            while (maxDepth-- > 0) {
                X509Certificate cert = chain.get(chain.size() - 1);

                X500Principal issuer = cert.getIssuerX500Principal();

                // Check if we found the root CA
                if (issuer.equals(cert.getSubjectX500Principal()))
                    break;

                boolean found = false;

                for (X509Certificate caCert : trustedCertificates) {
                    X500Principal subject = caCert.getSubjectX500Principal();
                    if (subject.equals(issuer)) {
                        try {
                            cert.verify(caCert.getPublicKey());
                            caCert.checkValidity();
                            chain.add(caCert);
                            modified = true;
                            found = true;
                            break;
                        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException
                                | SignatureException e) {
                            // Skip invalid certificates
                        }
                    }
                }

                if (!found)
                    break;
            }

            if (!modified || maxDepth == 0)
                return certPath;

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return factory.generateCertPath(chain);
        } catch (CertificateException e) {
            // Just ignore the exception
        }
        return certPath;
    }
}
