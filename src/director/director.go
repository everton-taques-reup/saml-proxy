package director

import (
	"errors"
	"fmt"
	"github.com/everton-taques-reup/saml-proxy/sharedKernel"
	"github.com/google/uuid"
	"net/http"
)

const (
	XForwardedProto = "X-Forwarded-Proto"
	XForwardedHost  = "X-Forwarded-Host"
	XForwardedURI   = "X-Forwarded-Uri"
	SamlRootURL     = "saml-root-url"
)

type Director struct {
	Logger sharedKernel.Logger
}

// GetRedirect determines the full URL or URI path to redirect clients to once
// authenticated with the OAuthProxy.
// Strategy priority (first legal result is used):
// - `rd` querysting parameter
// - `X-Auth-Request-Redirect` header
// - `X-Forwarded-(Proto|Host|Uri)` headers (when ReverseProxy mode is enabled)
// - `X-Forwarded-(Proto|Host)` if `Uri` has the ProxyPath (i.e. /oauth2/*)
// - `X-Forwarded-Uri` direct URI path (when ReverseProxy mode is enabled)
// - `req.URL.RequestURI` if not under the ProxyPath (i.e. /oauth2/*)
// - `/`
func (d Director) GetRedirect(req *http.Request) (string, error) {
	// Generate or extract correlation ID for request tracing
	correlationID := req.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = uuid.New().String()
	}

	// Log start of GetRedirect
	d.Logger.Info(fmt.Sprintf("Retrieving redirect URL [correlation_id=%s, method=%s, path=%s, client_ip=%s]", correlationID, req.Method, req.URL.Path, req.RemoteAddr))

	query := req.URL.Query()
	redirectUrl := query.Get("rd")
	if redirectUrl == "" {
		d.Logger.Info(fmt.Sprintf("DEBUG: No 'rd' query parameter found, checking other redirect strategies [correlation_id=%s]", correlationID))
		// Note: Other redirect strategies from the comment are not implemented in the code.
		// If needed, they can be added with appropriate logging.
	}

	protocol := sharedKernel.GetEnvWithFallbackString("SAML_PROXY_PROTOCOL", "https")
	d.Logger.Info(fmt.Sprintf("DEBUG: Retrieved protocol [correlation_id=%s, protocol=%s]", correlationID, protocol))

	redirectUrl = fmt.Sprintf("%s://%s", protocol, redirectUrl)

	// Log successful redirect URL creation
	d.Logger.Info(fmt.Sprintf("DEBUG: Generated redirect URL [correlation_id=%s, redirect_url=%s]", correlationID, redirectUrl))

	return redirectUrl, nil
}

func (d Director) GetRootUrl(req *http.Request) (string, error) {
	// Generate or extract correlation ID for request tracing
	correlationID := req.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = uuid.New().String()
	}

	// Log start of GetRootUrl
	d.Logger.Info(fmt.Sprintf("Retrieving root URL [correlation_id=%s, method=%s, path=%s, client_ip=%s]", correlationID, req.Method, req.URL.Path, req.RemoteAddr))

	protocol := req.Header.Get(XForwardedProto)
	if protocol == "" {
		d.Logger.Failure(errors.New(fmt.Sprintf("missing %s header [correlation_id=%s]", XForwardedProto, correlationID)))
		return "", errors.New(XForwardedProto + " header is missing")
	}

	// Log protocol header
	d.Logger.Info(fmt.Sprintf("DEBUG: Retrieved protocol header [correlation_id=%s, protocol=%s]", correlationID, protocol))

	host := req.Header.Get(XForwardedHost)
	if host == "" {
		d.Logger.Failure(errors.New(fmt.Sprintf("missing %s header [correlation_id=%s]", XForwardedHost, correlationID)))
		return "", errors.New(XForwardedHost + " header is missing")
	}

	// Log host header
	d.Logger.Info(fmt.Sprintf("DEBUG: Retrieved host header [correlation_id=%s, host=%s]", correlationID, host))

	rootUrl := fmt.Sprintf("%s://%s", protocol, host)

	// Log successful root URL creation
	d.Logger.Info(fmt.Sprintf("Generated root URL [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

	return rootUrl, nil
}