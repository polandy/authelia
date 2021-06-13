package handlers

import (
	"fmt"
	"net/http"

	"github.com/authelia/authelia/internal/authentication"
	"github.com/authelia/authelia/internal/middlewares"
)

// SecondFactorU2FSignPost handler for completing a signing request.
func SecondFactorU2FSignPost(u2fVerifier U2FVerifier) middlewares.AutheliaHandlerFunc {
	return func(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
		var requestBody signU2FRequestBody
		err := ctx.ParseBody(&requestBody)

		if err != nil {
			ctx.Error(err, mfaValidationFailedMessage)
			return
		}

		userSession := ctx.GetSession()
		if userSession.WebAuthnSessionData == nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("webauthn session data does not exist"), mfaValidationFailedMessage)
			return
		}

		_, err = web.FinishLogin(&userSession, *userSession.WebAuthnSessionData, req)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to finish webauthn signing of user %s: %s, %s",
				userSession.Username, err), mfaValidationFailedMessage)
			return
		}

		err = ctx.Providers.SessionProvider.RegenerateSession(ctx.RequestCtx)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regenerate session for user %s: %s", userSession.Username, err), mfaValidationFailedMessage)
			return
		}

		userSession.AuthenticationLevel = authentication.TwoFactor
		err = ctx.SaveSession(userSession)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to update authentication level with U2F: %s", err), mfaValidationFailedMessage)
			return
		}

		if userSession.OIDCWorkflowSession != nil {
			HandleOIDCWorkflowResponse(ctx)
		} else {
			Handle2FAResponse(ctx, requestBody.TargetURL)
		}
	}
}
