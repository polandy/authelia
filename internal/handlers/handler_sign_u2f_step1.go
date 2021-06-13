package handlers

import (
	"fmt"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/sirupsen/logrus"

	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/storage"
)

// SecondFactorU2FSignGet handler for initiating a signing request.
func SecondFactorU2FSignGet(ctx *middlewares.AutheliaCtx) {
	if ctx.XForwardedProto() == nil {
		ctx.Error(errMissingXForwardedProto, mfaValidationFailedMessage)
		return
	}

	if ctx.XForwardedHost() == nil {
		ctx.Error(errMissingXForwardedHost, mfaValidationFailedMessage)
		return
	}

	userSession := ctx.GetSession()
	keyHandleBytes, publicKeyBytes, err := ctx.Providers.StorageProvider.LoadU2FDeviceHandle(userSession.Username)

	if err != nil {
		if err == storage.ErrNoU2FDeviceHandle {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("No device handle found for user %s", userSession.Username), mfaValidationFailedMessage)
			return
		}

		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to retrieve U2F device handle: %s", err), mfaValidationFailedMessage)

		return
	}

	/*var registration u2f.Registration
	registration.KeyHandle = keyHandleBytes
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	registration.PubKey.Curve = elliptic.P256()
	registration.PubKey.X = x
	registration.PubKey.Y = y

	// Save the challenge and registration for use in next request
	userSession.U2FRegistration = &session.U2FRegistration{
		KeyHandle: keyHandleBytes,
		PublicKey: publicKeyBytes,
	}
	userSession.U2FChallenge = challenge*/

	cred := webauthn.Credential{
		ID:        keyHandleBytes,
		PublicKey: publicKeyBytes,
	}

	/*cred, err := session.FromGOB64(credentialStr)
	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to deserialize webauthn credential: %s", err), mfaValidationFailedMessage)
		return
	}*/
	userSession.AddCredential(&cred)

	appID := fmt.Sprintf("%s://%s", ctx.XForwardedProto(), ctx.XForwardedHost())
	logrus.Debug("appid ==== ", appID)
	options, sessionData, err := web.BeginLogin(&userSession,
		webauthn.WithAssertionExtensions(protocol.AuthenticationExtensions{
			"appid": appID,
		}))

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to begin webauthn login: %s", err), mfaValidationFailedMessage)
		return
	}

	userSession.WebAuthnSessionData = sessionData

	err = ctx.SaveSession(userSession)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to save U2F challenge and registration in session: %s", err), mfaValidationFailedMessage)
		return
	}

	err = ctx.SetJSONBody(options)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to set sign request in body: %s", err), mfaValidationFailedMessage)
		return
	}
}
