package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/internal/logging"
	"github.com/authelia/authelia/internal/utils"
)

var alphaNumericRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// ServeTemplatedFile serves a templated version of a specified file,
// this is utilised to pass information between the backend and frontend
// and generate a nonce to support a restrictive CSP while using material-ui.
func ServeTemplatedFile(publicDir, file, rememberMe, resetPassword, session, theme string) fasthttp.RequestHandler {
	logger := logging.Logger()

	f, err := assets.Open(publicDir + file)
	if err != nil {
		logger.Fatalf("Unable to open %s: %s", file, err)
	}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		logger.Fatalf("Unable to read %s: %s", file, err)
	}

	tmpl, err := template.New("file").Parse(string(b))
	if err != nil {
		logger.Fatalf("Unable to parse %s template: %s", file, err)
	}

	return func(ctx *fasthttp.RequestCtx) {
		base := ""
		if baseURL := ctx.UserValue("base_url"); baseURL != nil {
			base = baseURL.(string)
		}

		nonce := utils.RandomString(32, alphaNumericRunes)

		switch extension := filepath.Ext(file); extension {
		case ".html":
			ctx.SetContentType("text/html; charset=utf-8")
		default:
			ctx.SetContentType("text/plain; charset=utf-8")
		}

		switch {
		case publicDir == swaggerAssets:
			ctx.Response.Header.Add("Content-Security-Policy", fmt.Sprintf("base-uri 'self' ; default-src 'self' ; img-src 'self' https://validator.swagger.io data: ; object-src 'none' ; script-src 'self' 'unsafe-inline' 'nonce-%s' ; style-src 'self' 'nonce-%s'", nonce, nonce))
		case os.Getenv("ENVIRONMENT") == dev:
			ctx.Response.Header.Add("Content-Security-Policy", fmt.Sprintf("default-src 'self' 'unsafe-eval'; object-src 'none'; style-src 'self' 'nonce-%s'", nonce))
		default:
			ctx.Response.Header.Add("Content-Security-Policy", fmt.Sprintf("default-src 'self' ; object-src 'none'; style-src 'self' 'nonce-%s'", nonce))
		}

		err := tmpl.Execute(ctx.Response.BodyWriter(), struct{ Base, CSPNonce, RememberMe, ResetPassword, Session, Theme string }{Base: base, CSPNonce: nonce, RememberMe: rememberMe, ResetPassword: resetPassword, Session: session, Theme: theme})
		if err != nil {
			ctx.Error("an error occurred", 503)
			logger.Errorf("Unable to execute template: %v", err)

			return
		}
	}
}

func writeHealthCheckEnv(disabled bool, scheme, host, path string, port int) (err error) {
	if disabled {
		return nil
	}

	_, err = os.Stat("/app/healthcheck.sh")
	if err != nil {
		return nil
	}

	_, err = os.Stat("/app/.healthcheck.env")
	if err != nil {
		return nil
	}

	file, err := os.OpenFile("/app/.healthcheck.env", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	defer func() {
		_ = file.Close()
	}()

	if host == "0.0.0.0" {
		host = "localhost"
	}

	_, err = file.WriteString(fmt.Sprintf(healthCheckEnv, scheme, host, port, path))

	return err
}
