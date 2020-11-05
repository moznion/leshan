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
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;

public abstract class BaseCertificateVerifier implements CertificateVerifier {

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
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
}
