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
package io.enmasse.systemtest;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class KeycloakClient {

    private final Endpoint endpoint;
    private final KeycloakCredentials credentials;

    public KeycloakClient(Endpoint endpoint, KeycloakCredentials credentials) {
        this.endpoint = endpoint;
        this.credentials = credentials;
    }

    public void createUser(String realm, String userName, String password) throws Exception {
        createUser(realm, userName, password, 3, TimeUnit.MINUTES);
    }

    public void createUser(String realm, String userName, String password, long timeout, TimeUnit timeUnit) throws Exception {

        int maxRetries = 10;
        try (CloseableKeycloak keycloak = new CloseableKeycloak(endpoint, credentials)) {
            RealmResource realmResource = waitForRealm(keycloak.get(), realm, timeout, timeUnit);

            for (int retries = 0; retries < maxRetries; retries++) {
                try {
                    if (realmResource.users().search(userName).isEmpty()) {
                        UserRepresentation userRep = new UserRepresentation();
                        userRep.setUsername(userName);
                        CredentialRepresentation cred = new CredentialRepresentation();
                        cred.setType(CredentialRepresentation.PASSWORD);
                        cred.setValue(password);
                        cred.setTemporary(false);
                        userRep.setCredentials(Arrays.asList(cred));
                        userRep.setEnabled(true);
                        Response response = keycloak.get().realm(realm).users().create(userRep);
                        if (response.getStatus() != 201) {
                            throw new RuntimeException("Unable to create user: " + response.getStatus());
                        }
                    } else {
                        Logging.log.info("User " + userName + " already created, skipping");
                    }
                    break;
                } catch (Exception e) {
                    Logging.log.info("Exception querying keycloak ({}), retrying", e.getMessage());
                    Thread.sleep(2000);
                }
            }
        }
    }


    private RealmResource waitForRealm(Keycloak keycloak, String realmName, long timeout, TimeUnit timeUnit) throws Exception {
        Logging.log.info("Waiting for realm {} to exist", realmName);
        long endTime = System.currentTimeMillis() + timeUnit.toMillis(timeout);
        RealmResource realmResource = null;
        while (System.currentTimeMillis() < endTime) {
            realmResource = getRealmResource(keycloak, realmName);
            if (realmResource != null) {
                return realmResource;
            }
            Thread.sleep(5000);
        }

        if (realmResource == null) {
            realmResource = getRealmResource(keycloak, realmName);
        }

        if (realmResource != null) {
            return realmResource;
        }

        throw new TimeoutException("Timed out waiting for realm " + realmName + " to exist");
    }

    private RealmResource getRealmResource(Keycloak keycloak, String realmName) throws Exception {
        return TestUtils.doRequestNTimes(10, () -> {
            List<RealmRepresentation> realms = keycloak.realms().findAll();
            for (RealmRepresentation realm : realms) {
                if (realm.getRealm().equals(realmName)) {
                    return keycloak.realm(realmName);
                }
            }
            return null;
        });
    }

    public void deleteUser(String realm, String userName) throws Exception {
        try (CloseableKeycloak keycloak = new CloseableKeycloak(endpoint, credentials)) {
            TestUtils.doRequestNTimes(10, () -> keycloak.get().realm(realm).users().delete(userName));
        }
    }

    private static class CloseableKeycloak implements AutoCloseable {

        private final Keycloak keycloak;

        private CloseableKeycloak(Endpoint endpoint, KeycloakCredentials credentials) {
            Logging.log.info("Logging into keycloak with {}/{}", credentials.getUsername(), credentials.getPassword());
            this.keycloak = Keycloak.getInstance("http://" + endpoint.getHost() + ":" + endpoint.getPort() + "/auth",
                "master", credentials.getUsername(), credentials.getPassword(), "admin-cli");
        }

        public Keycloak get() {
            return keycloak;
        }

        @Override
        public void close() {
            keycloak.close();
        }
    }
}
