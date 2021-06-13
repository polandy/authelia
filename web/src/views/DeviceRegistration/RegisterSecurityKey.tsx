import React, { useState, useEffect, useCallback } from "react";

import { makeStyles, Typography, Button } from "@material-ui/core";
import { useHistory, useLocation } from "react-router";

import FingerTouchIcon from "../../components/FingerTouchIcon";
import { useNotifications } from "../../hooks/NotificationsContext";
import LoginLayout from "../../layouts/LoginLayout";
import { FirstFactorPath } from "../../services/Api";
import {
    completeU2FRegistrationProcessStep1,
    completeU2FRegistrationProcessStep2,
} from "../../services/RegisterDevice";
import { bufferEncode, bufferDecode } from "../../utils/Buffer";
import { extractIdentityToken } from "../../utils/IdentityToken";

const RegisterSecurityKey = function () {
    const style = useStyles();
    const history = useHistory();
    const location = useLocation();
    const { createErrorNotification } = useNotifications();
    const [, setRegistrationInProgress] = useState(false);

    const processToken = extractIdentityToken(location.search);

    const handleBackClick = () => {
        history.push(FirstFactorPath);
    };

    const registerStep1 = useCallback(async () => {
        if (!processToken) {
            return;
        }
        try {
            setRegistrationInProgress(true);
            const credentialCreationOptions = await completeU2FRegistrationProcessStep1(processToken);
            if (credentialCreationOptions.publicKey) {
                credentialCreationOptions.publicKey.challenge = bufferDecode(
                    credentialCreationOptions.publicKey.challenge,
                );
                credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
            }

            const credential = (await navigator.credentials.create({
                publicKey: credentialCreationOptions.publicKey,
            })) as any;
            const attestationObject = credential.response.attestationObject;
            const clientDataJSON = credential.response.clientDataJSON;
            const rawId = credential.rawId;
            const payload = {
                id: credential.id,
                rawId: bufferEncode(rawId),
                type: credential.type,
                response: {
                    attestationObject: bufferEncode(attestationObject),
                    clientDataJSON: bufferEncode(clientDataJSON),
                },
            };

            await completeU2FRegistrationProcessStep2(payload);
            setRegistrationInProgress(false);
            history.push(FirstFactorPath);
        } catch (err) {
            console.error(err);
            createErrorNotification(
                "Failed to register your security key. The identity verification process might have timed out.",
            );
        }
    }, [processToken, createErrorNotification, history]);

    useEffect(() => {
        registerStep1();
    }, [registerStep1]);

    return (
        <LoginLayout title="Touch Security Key">
            <div className={style.icon}>
                <FingerTouchIcon size={64} animated />
            </div>
            <Typography className={style.instruction}>Touch the token on your security key</Typography>
            <Button color="primary" onClick={handleBackClick}>
                Retry
            </Button>
            <Button color="primary" onClick={handleBackClick}>
                Cancel
            </Button>
        </LoginLayout>
    );
};

export default RegisterSecurityKey;

const useStyles = makeStyles((theme) => ({
    icon: {
        paddingTop: theme.spacing(4),
        paddingBottom: theme.spacing(4),
    },
    instruction: {
        paddingBottom: theme.spacing(4),
    },
}));
