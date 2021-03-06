/*
 * Copyright 2017 Red Hat Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.enmasse.keycloak.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Map;

public class KeycloakParams {

    private static final Logger log = LoggerFactory.getLogger(KeycloakParams.class);

    private final String host;
    private final int httpPort;
    private final String adminUser;
    private final String adminPassword;
    private final KeyStore keyStore;

    public KeycloakParams(String host, int httpPort, String adminUser, String adminPassword, KeyStore keyStore) {
        this.host = host;
        this.httpPort = httpPort;
        this.adminUser = adminUser;
        this.adminPassword = adminPassword;
        this.keyStore = keyStore;
    }

    public static KeycloakParams fromEnv(Map<String, String> env) throws Exception {
        String host = getEnvOrThrow(env, "STANDARD_AUTHSERVICE_SERVICE_HOST");
        int httpPort = Integer.parseInt(getEnvOrThrow(env, "STANDARD_AUTHSERVICE_SERVICE_PORT_HTTPS"));
        String adminUser = getEnvOrThrow(env, "STANDARD_AUTHSERVICE_ADMIN_USER");
        String adminPassword = getEnvOrThrow(env, "STANDARD_AUTHSERVICE_ADMIN_PASSWORD");
        KeyStore keyStore = createKeyStore(env);

        return new KeycloakParams(host, httpPort, adminUser, adminPassword, keyStore);
    }

    private static KeyStore createKeyStore(Map<String, String> env) throws Exception {
        String authServiceCa = getEnvOrThrow(env, "STANDARD_AUTHSERVICE_CA_CERT");

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            keyStore.setCertificateEntry("standard-authservice",
                    cf.generateCertificate(new ByteArrayInputStream(authServiceCa.getBytes("UTF-8"))));

            return keyStore;
        } catch (Exception ignored) {
            log.warn("Error creating keystore for authservice CA", ignored);
            throw ignored;
        }
    }

    private static String getEnvOrThrow(Map<String, String> envMap, String env) {
        String value = envMap.get(env);
        if (value == null) {
            throw new IllegalArgumentException("Required environment variable " + env + " is missing");
        }
        return value;
    }

    public String getHost() {
        return host;
    }

    public int getHttpPort() {
        return httpPort;
    }

    public String getAdminUser() {
        return adminUser;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
