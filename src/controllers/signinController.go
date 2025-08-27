package controllers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/everton-taques-reup/saml-proxy/director"
	"github.com/everton-taques-reup/saml-proxy/domain"
	"github.com/everton-taques-reup/saml-proxy/sharedKernel"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
)

type SigninController struct {
	Router     *gin.Engine
	SamlDomain *domain.SamlDomain
	Logger     sharedKernel.Logger
	Director   director.Director
	rootUrl    string
	middleware *samlsp.Middleware
}

func (c *SigninController) Handler() gin.IRoutes {
	return c.Router.GET("/saml/sign_in", func(context *gin.Context) {
		// Generate or extract correlation ID for request tracing
		correlationID := context.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		// Log request start with metadata
		c.Logger.Info(fmt.Sprintf("Handling SAML sign-in request [correlation_id=%s, method=%s, path=%s, client_ip=%s]", correlationID, context.Request.Method, context.Request.URL.Path, context.ClientIP()))

		// Pass logger to Director
		c.Director.Logger = c.Logger

		// Get root URL
		rootUrl, err := c.Director.GetRootUrl(context.Request)
		if err != nil {
			c.Logger.Failure(errors.New(fmt.Sprintf("failed to get root URL [correlation_id=%s]: %s", correlationID, err.Error())))
			context.JSON(400, gin.H{"message": "Invalid root URL"})
			return
		}

		// Log successful root URL retrieval
		c.Logger.Info(fmt.Sprintf("DEBUG: Retrieved root URL [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		c.rootUrl = rootUrl
		// Get SAML provider
		c.middleware, err = c.SamlDomain.GetProvider(c.rootUrl)
		if err != nil {
			c.Logger.Failure(errors.New(fmt.Sprintf("failed to get SAML provider [correlation_id=%s, root_url=%s]: %s", correlationID, rootUrl, err.Error())))
			context.JSON(400, gin.H{"message": "Invalid SAML provider"})
			return
		}

		// Log successful provider retrieval
		c.Logger.Info(fmt.Sprintf("DEBUG: Retrieved SAML provider [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		// Log start of auth flow
		c.Logger.Info(fmt.Sprintf("DEBUG: Starting SAML auth flow [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		c.handleStartAuthFlow(context.Writer, context.Request, correlationID)
	})
}

func (c SigninController) handleStartAuthFlow(w http.ResponseWriter, r *http.Request, correlationID string) {
	// Check for potential redirect loop
	if r.URL.Path == c.middleware.ServiceProvider.AcsURL.Path {
		c.Logger.Failure(errors.New(fmt.Sprintf("attempted to wrap Middleware with RequireAccount, causing potential redirect loop [correlation_id=%s, path=%s, acs_url=%s]", correlationID, r.URL.Path, c.middleware.ServiceProvider.AcsURL.Path)))
		panic("don't wrap Middleware with RequireAccount")
	}

	// Log start of auth flow
	c.Logger.Info(fmt.Sprintf("Starting SAML auth flow [correlation_id=%s, root_url=%s]", correlationID, c.rootUrl))

	var binding, bindingLocation string
	if c.middleware.Binding != "" {
		binding = c.middleware.Binding
		bindingLocation = c.middleware.ServiceProvider.GetSSOBindingLocation(binding)
	} else {
		binding = saml.HTTPRedirectBinding
		bindingLocation = c.middleware.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = c.middleware.ServiceProvider.GetSSOBindingLocation(binding)
		}
	}

	// Log selected binding
	c.Logger.Info(fmt.Sprintf("DEBUG: Selected SAML binding [correlation_id=%s, binding=%s, binding_location=%s]", correlationID, binding, bindingLocation))

	// Create authentication request
	authReq, err := c.middleware.ServiceProvider.MakeAuthenticationRequest(bindingLocation, binding, saml.HTTPPostBinding)
	if err != nil {
		c.Logger.Failure(errors.New(fmt.Sprintf("failed to create SAML authentication request [correlation_id=%s, binding=%s, binding_location=%s]: %s", correlationID, binding, bindingLocation, err.Error())))
		http.Error(w, "Failed to create authentication request", http.StatusInternalServerError)
		return
	}

	// Log successful authentication request creation
	c.Logger.Info(fmt.Sprintf("DEBUG: Created SAML authentication request [correlation_id=%s, request_id=%s]", correlationID, authReq.ID))

	// Track request
	relayState, err := c.trackRequest(w, r, authReq.ID, correlationID)
	if err != nil {
		c.Logger.Failure(errors.New(fmt.Sprintf("failed to track SAML request [correlation_id=%s, request_id=%s]: %s", correlationID, authReq.ID, err.Error())))
		http.Error(w, "Failed to track request", http.StatusInternalServerError)
		return
	}

	// Log successful request tracking
	c.Logger.Info(fmt.Sprintf("DEBUG: Tracked SAML request [correlation_id=%s, relay_state=%s]", correlationID, relayState))

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, &c.middleware.ServiceProvider)
		if err != nil {
			c.Logger.Failure(errors.New(fmt.Sprintf("failed to create redirect URL for SAML authentication [correlation_id=%s, relay_state=%s]: %s", correlationID, relayState, err.Error())))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`something went wrong`))
			return
		}
		// Log redirect
		c.Logger.Info(fmt.Sprintf("Redirecting for SAML authentication [correlation_id=%s, redirect_url=%s, relay_state=%s]", correlationID, redirectURL.String(), relayState))
		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}
	if binding == saml.HTTPPostBinding {
		// Log POST binding
		c.Logger.Info(fmt.Sprintf("Serving SAML POST binding [correlation_id=%s, relay_state=%s]", correlationID, relayState))
		w.Header().Add("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		w.Header().Add("Content-type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body>`))
		w.Write(authReq.Post(relayState))
		w.Write([]byte(`</body></html>`))
		return
	}
	c.Logger.Failure(errors.New(fmt.Sprintf("unexpected binding type [correlation_id=%s, binding=%s]", correlationID, binding)))
	panic("not reached")
}

func (c SigninController) trackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string, correlationID string) (string, error) {
	// Log start of request tracking
	c.Logger.Info(fmt.Sprintf("DEBUG: Tracking SAML request [correlation_id=%s, saml_request_id=%s]", correlationID, samlRequestID))

	// Pass logger to Director
	c.Director.Logger = c.Logger

	redirect, err := c.Director.GetRedirect(r)
	if err != nil {
		c.Logger.Failure(errors.New(fmt.Sprintf("failed to get redirect URL [correlation_id=%s, saml_request_id=%s]: %s", correlationID, samlRequestID, err.Error())))
		return "", err
	}

	// Log redirect URL
	c.Logger.Info(fmt.Sprintf("DEBUG: Retrieved redirect URL [correlation_id=%s, saml_request_id=%s, redirect_url=%s]", correlationID, samlRequestID, redirect))

	trackedRequest := samlsp.TrackedRequest{
		Index:         base64.RawURLEncoding.EncodeToString(sharedKernel.RandomBytes(42)),
		SAMLRequestID: samlRequestID,
		URI:           redirect,
	}
	signedTrackedRequest, err := c.middleware.RequestTracker.(samlsp.CookieRequestTracker).Codec.Encode(trackedRequest)
	if err != nil {
		c.Logger.Failure(errors.New(fmt.Sprintf("failed to encode tracked request [correlation_id=%s, saml_request_id=%s]: %s", correlationID, samlRequestID, err.Error())))
		return "", err
	}

	// Log successful encoding of tracked request
	c.Logger.Info(fmt.Sprintf("DEBUG: Encoded tracked request [correlation_id=%s, saml_request_id=%s, index=%s]", correlationID, samlRequestID, trackedRequest.Index))

	http.SetCookie(w, &http.Cookie{
		Name:     c.middleware.RequestTracker.(samlsp.CookieRequestTracker).NamePrefix + trackedRequest.Index,
		Value:    signedTrackedRequest,
		MaxAge:   int(c.middleware.RequestTracker.(samlsp.CookieRequestTracker).MaxAge.Seconds()),
		HttpOnly: true,
		SameSite: c.middleware.RequestTracker.(samlsp.CookieRequestTracker).SameSite,
		Secure:   c.middleware.RequestTracker.(samlsp.CookieRequestTracker).ServiceProvider.AcsURL.Scheme == "https",
		Path:     c.middleware.RequestTracker.(samlsp.CookieRequestTracker).ServiceProvider.AcsURL.Path,
	})

	// Log successful cookie setting
	c.Logger.Info(fmt.Sprintf("DEBUG: Set tracking cookie [correlation_id=%s, saml_request_id=%s, cookie_name=%s]", correlationID, samlRequestID, c.middleware.RequestTracker.(samlsp.CookieRequestTracker).NamePrefix+trackedRequest.Index))

	return trackedRequest.Index, nil
}