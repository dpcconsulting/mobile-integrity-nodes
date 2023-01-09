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


package hu.dpc.fr.appattestnode;

import static ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment.DEVELOPMENT;
import static ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment.PRODUCTION;
import static java.util.stream.Collectors.toMap;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.Action.send;
//import static org.forgerock.openam.auth.node.api.AbstractDecisionNode.goTo;

import java.util.*;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.MetadataCallback;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.google.common.collect.ImmutableList;

import ch.veehait.devicecheck.appattest.AppleAppAttest;
import ch.veehait.devicecheck.appattest.common.App;
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation;
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator;


/**
 * A node that implements Apple iOS App Attest server-side tasks as part of an authentication tree.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = AppAttest.Config.class)
public class AppAttest extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(AppAttest.class);
    private final Config config;
    private final Realm realm;
    private final static String HU_DPC_FR_APPATTEST_CHALLENGE = "hu.dpc.fr.appattest-challenge";

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The iOS app's bundle id.
         */
        @Attribute(order = 100, requiredValue = true)
        default String bundleId() {
            return "hu.dpc.sample";
        }

        /**
         * The Apple developer Team id.
         */
        @Attribute(order = 200, requiredValue = true)
        default String teamId() {
            return "123456789A";
        }

        /**
         * DEVELOPMENT OR PRODUCTION
         */
        @Attribute(order = 300)
        default String environment() {
            return "DEVELOPMENT";
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
    public AppAttest(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        if (!context.hasCallbacks()) {
            //first invocation, let's generate callbacks
            logger.info("APPATTEST: sending callbacks");
            String challenge = UUID.randomUUID().toString();
            logger.info("APPATTEST: Challenge UUID: " + challenge);

            context.getStateFor(this).putShared(HU_DPC_FR_APPATTEST_CHALLENGE, challenge);
            logger.info("APPATTEST: check challenge in shared state: " + context.getStateFor(this).get(HU_DPC_FR_APPATTEST_CHALLENGE).toString());

            return sendCallbacks(createMetadataFromChallenge(challenge), createHiddenValueForKeyId(), createHiddenValueForAttestation());
        } else {
            //process the returned callbacks
            logger.info("APPATTEST: receiving callbacks");

            String challenge = context.getStateFor(this).get(HU_DPC_FR_APPATTEST_CHALLENGE).asString();
            logger.info("APPATTEST: challenge from shared state: " + challenge);

            List<HiddenValueCallback> hiddenValueCallbackList = context.getCallbacks(HiddenValueCallback.class);
            logger.info("APPATTEST: number of hiddenvaluecallbacks: " + hiddenValueCallbackList.size());

            Map<String, HiddenValueCallback> hiddenValueCallbackMap = hiddenValueCallbackList.stream()
                    .collect(toMap(c -> c.getId().toString() , c -> c));

            String keyId = hiddenValueCallbackMap.get("keyId").getValue().toString();
            logger.info("APPATTEST: hiddenvaluecallback keyId: " + keyId);
            String attestation = hiddenValueCallbackMap.get("attestation").getValue().toString();
            logger.info("APPATTEST: hiddenvaluecallback attestation: " + keyId);

            if (keyId != null && attestation != null) {

                Action gotoAction = gotoNext(validateAttestation(config.teamId(), config.bundleId(), keyId, challenge, attestation));
                context.getStateFor(this).remove(HU_DPC_FR_APPATTEST_CHALLENGE);
                return gotoAction;

            } else {
                logger.error("APPATTEST: Haven't received both a MetadataCallback and a HiddenValueCallback");
                context.getStateFor(this).remove(HU_DPC_FR_APPATTEST_CHALLENGE);
                return gotoNext(false);
            }
        }
    }

    private boolean validateAttestation(String teamId, String bundleId, String keyId, String challenge, String attestation) {

        logger.info("APPATTEST: validateAttestation(" + teamId + ", " + bundleId + ", " + keyId + ", " + challenge + ", " + attestation + ")");

        // Create an instance of AppleAppAttest specific to a given iOS app, development team and
        // Apple Appattest environment
        logger.info("APPATTEST: env: " + config.environment());

        AppleAppAttestEnvironment env = config.environment().equals("DEVELOPMENT") ? DEVELOPMENT : PRODUCTION;
        logger.info("APPATTEST: environment: " + env);
        try {
            App app = new App(teamId, bundleId);
            logger.info("APPATTEST: created App: " + app);

            AppleAppAttest appleAppAttest = new AppleAppAttest(app, env);
            logger.info("APPATTEST: created AppleAppAttest" + appleAppAttest);

            // Create an AttestationValidator instance
            AttestationValidator attestationValidator = appleAppAttest.createAttestationValidator();
            logger.info("APPATTEST: created AttestationValidator: " + attestationValidator);

            // Validate a single attestation object. Throws an AttestationException if a validation
            // error occurs.
            UUID uuid = UUID.fromString(challenge);
            logger.info("APPATTEST: UUID from string: " + uuid.toString());

            // try {
            byte[] decodedAttestation = Base64.getDecoder().decode(attestation);
            logger.info("APPATTEST: decoded attestation: " + Arrays.toString(decodedAttestation));

            ValidatedAttestation result = attestationValidator.validate(decodedAttestation, keyId, challenge.getBytes());
            logger.info("APPATTEST: validation result" + result);

            return true;
        } catch (Exception /*AttestationException*/ x) {
            logger.error("APPATTEST: validation exception: " + x.getMessage(), x);
            return false;
        }

    }


    private MetadataCallback createMetadataFromChallenge(String challenge) {
        MetadataCallback metadataCallback = new MetadataCallback(json(object(
                field("_action", "appattest"),
                field("challenge", challenge),
                field("_type", "AppAttest")
        )));
        logger.info("APPATTEST: MetadataCallback: " + metadataCallback);
        return metadataCallback;
    }

    private HiddenValueCallback createHiddenValueForAttestation() {
        return new HiddenValueCallback("attestation", "false");
    }

    private HiddenValueCallback createHiddenValueForKeyId() {
        return new HiddenValueCallback("keyId", "false");
    }

    private Action sendCallbacks(Callback... callbacks) {
        logger.info("APPATTEST: sending callbacks: " + callbacks);
        return send(ImmutableList.copyOf(callbacks)).build();
    }

    private Action gotoNext(boolean outcome) {
        return goTo(outcome).build();
    }

}
