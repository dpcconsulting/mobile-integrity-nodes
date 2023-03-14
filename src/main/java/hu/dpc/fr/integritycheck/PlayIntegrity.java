/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 *
 * Portions Copyright 2023 DPC Consulting Kft
 *
 * Includes App Attestation library by Vincent Haupert
 * from https://github.com/veehaitch/devicecheck-appattest/tree/v0.9.4 (Apache License 2.0)

 */


package hu.dpc.fr.integritycheck;

import com.google.api.client.googleapis.services.GoogleClientRequestInitializer;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.playintegrity.v1.PlayIntegrityRequestInitializer;
import com.google.api.services.playintegrity.v1.PlayIntegrityScopes;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenRequest;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenResponse;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.MetadataCallback;
import hu.dpc.fr.integritycheck.util.PlayCheckLevel;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;


import static hu.dpc.fr.integritycheck.util.PlayCheckLevel.NonceDeviceApp;
import static hu.dpc.fr.integritycheck.util.PlayCheckLevel.NonceOnly;
import static java.util.stream.Collectors.toMap;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.Action.send;


/**
 * A node that implements Google Play Integrity Check server-side tasks as part of an authentication tree.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = PlayIntegrity.Config.class)
public class PlayIntegrity extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(PlayIntegrity.class);
    private final Config config;
    private final Realm realm;
    private final static String HU_DPC_FR_INTEGRITY_NONCE = "hu.dpc.fr.integrity-nonce";

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The Android app's package name.
         */
        @Attribute(order = 100, requiredValue = true)
        default String packageName() {
            return "hu.dpc.sample";
        }

        /**
         * The Android app's name.
         */
        @Attribute(order = 200, requiredValue = true)
        default String appName() {
            return "hu.dpc.sample";
        }

        /**
         * The Google Application Service Account Key (JSON string).
         */
        @Attribute(order = 300, requiredValue = true)
        default String googleCredentials() {
            return "{\"type\": \"service_account\",\"project_id\": \"bx-integrity\",\"private_key_id\": \"xxxx\",\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nXXXX\\n-----END PRIVATE KEY-----\\n\",\"client_email\": \"XXXX@XXXX.iam.gserviceaccount.com\",\"client_id\": \"XXXXXXX\",\"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\"token_uri\": \"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/XXXX%40XXXX.iam.gserviceaccount.com\"}";
        }

        /**
         * Required check level
         */
        @Attribute(order = 400, requiredValue = true)
        default PlayCheckLevel checkLevel() {
            return NonceOnly;
        }

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm  The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public PlayIntegrity(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        if (!context.hasCallbacks()) {
            //first invocation, let's generate callbacks
            logger.info("PLAYINTEGRITY: sending callbacks");
            String nonce = UUID.randomUUID().toString();
            logger.info("PLAYINTEGRITY: Nonce UUID: " + nonce);

            context.getStateFor(this).putShared(HU_DPC_FR_INTEGRITY_NONCE, nonce);
            logger.info("PLAYINTEGRITY: check nonce in shared state: " + context.getStateFor(this).get(HU_DPC_FR_INTEGRITY_NONCE).toString());

            return sendCallbacks(createMetadataFromNonce(nonce), createHiddenValueForToken());
        } else {
            //process the returned callbacks
            logger.info("PLAYINTEGRITY: receiving callbacks");

            String nonce = context.getStateFor(this).get(HU_DPC_FR_INTEGRITY_NONCE).asString();
            logger.info("PLAYINTEGRITY: nonce from shared state: " + nonce);

            List<HiddenValueCallback> hiddenValueCallbackList = context.getCallbacks(HiddenValueCallback.class);
            logger.info("PLAYINTEGRITY: number of hiddenvaluecallbacks: " + hiddenValueCallbackList.size());

            Map<String, HiddenValueCallback> hiddenValueCallbackMap = hiddenValueCallbackList.stream()
                    .collect(toMap(c -> c.getId().toString(), c -> c));

            String token = hiddenValueCallbackMap.get("token").getValue().toString();
            logger.info("PLAYINTEGRITY: hiddenvaluecallback token: " + token);


            if (token != null) {

                Action gotoAction = gotoNext(validateIntegrityToken(token, nonce));
                context.getStateFor(this).remove(HU_DPC_FR_INTEGRITY_NONCE);
                return gotoAction;

            } else {
                logger.error("PLAYINTEGRITY: Haven't received both a MetadataCallback and a HiddenValueCallback");
                context.getStateFor(this).remove(HU_DPC_FR_INTEGRITY_NONCE);
                return gotoNext(false);
            }
        }
    }

    private boolean validateIntegrityToken(String token, String nonce) {

        logger.info("PLAYINTEGRITY: validate token for (config: [" + config.packageName() + ", " + config.appName() + ", "
                + config.googleCredentials() + ", " + config.checkLevel() + "]; token: "
                + token + ", nonce: " + nonce + ")");

        DecodeIntegrityTokenRequest requestObj = new DecodeIntegrityTokenRequest();
        requestObj.setIntegrityToken(token);

        GoogleCredentials credentials = null;
        DecodeIntegrityTokenResponse response = null;

        try {
            credentials = GoogleCredentials.fromStream(new ByteArrayInputStream(config.googleCredentials().getBytes(StandardCharsets.UTF_8)))
                    .createScoped(PlayIntegrityScopes.PLAYINTEGRITY);
            logger.info("PLAYINTEGRITY: credentials json: " + credentials);

            HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);

            HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
            JsonFactory JSON_FACTORY = new GsonFactory();
            GoogleClientRequestInitializer initialiser = new PlayIntegrityRequestInitializer();

            com.google.api.services.playintegrity.v1.PlayIntegrity play = new com.google.api.services.playintegrity.v1.PlayIntegrity.Builder(HTTP_TRANSPORT, JSON_FACTORY, requestInitializer)
                    .setApplicationName(config.appName())
                    .setGoogleClientRequestInitializer(initialiser)
                    .build();
            response = play.v1().decodeIntegrityToken(config.packageName(), requestObj).execute();

            logger.info("PLAYINTEGRITY: licensingVerdict: " + response.getTokenPayloadExternal().getAccountDetails().getAppLicensingVerdict());
            logger.info("PLAYINTEGRITY: apprecognitionverdict: " + response.getTokenPayloadExternal().getAppIntegrity().getAppRecognitionVerdict());
            logger.info("PLAYINTEGRITY: devicerecognitionverdict: " + response.getTokenPayloadExternal().getDeviceIntegrity().getDeviceRecognitionVerdict());
            logger.info("PLAYINTEGRITY: nonce: " + response.getTokenPayloadExternal().getRequestDetails().getNonce());
            logger.info("PLAYINTEGRITY: complete response: " + response);

            PlayCheckLevel checkLevel = config.checkLevel();

            if (nonce.equals(response.getTokenPayloadExternal().getRequestDetails().getNonce())) {
                if (checkLevel == NonceOnly) {
                    logger.info("PLAYINTEGRITY: NonceOnly: nonce OK");
                    return true;
                } else {
                    if (checkLevel == NonceDeviceApp) {
                        boolean verdict = "PLAY_RECOGNIZED".equals(response.getTokenPayloadExternal().getAppIntegrity().getAppRecognitionVerdict())
                              && response.getTokenPayloadExternal().getDeviceIntegrity().getDeviceRecognitionVerdict().contains("MEETS_DEVICE_INTEGRITY");
                        logger.info("PLAYINTEGRITY: NonceDeviceApp: verdict: " + verdict);
                        return verdict;
                    }
                }
            } else {
                logger.warn("PLAYINTEGRITY: nonce invalid");
                return false;
            }

        } catch (IOException e) {
           logger.error("PLAYINTEGRITY: error talking to Google: " + e.getMessage(), e);
           return false;
        }
        logger.warn("PLAYINTEGRITY: we should not get here ever :-)");
        return false;
    }


    private MetadataCallback createMetadataFromNonce(String nonce) {
        MetadataCallback metadataCallback = new MetadataCallback(json(object(
                field("_action", "integritycheck"),
                field("nonce", nonce),
                field("_type", "integritycheck")
        )));
        logger.info("PLAYINTEGRITY: MetadataCallback: " + metadataCallback);
        return metadataCallback;
    }

    private HiddenValueCallback createHiddenValueForToken() {
        return new HiddenValueCallback("token", "false");
    }

    private Action sendCallbacks(Callback... callbacks) {
        logger.info("PLAYINTEGRITY: sending callbacks: " + callbacks);
        return send(ImmutableList.copyOf(callbacks)).build();
    }

    private Action gotoNext(boolean outcome) {
        return goTo(outcome).build();
    }

}
