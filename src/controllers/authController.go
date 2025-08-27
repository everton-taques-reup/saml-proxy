package controllers

import (
	"fmt"
	"github.com/everton-taques-reup/saml-proxy/director"
	"github.com/everton-taques-reup/saml-proxy/domain"
	"github.com/everton-taques-reup/saml-proxy/sharedKernel"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthController struct {
	Router     *gin.Engine
	SamlDomain *domain.SamlDomain
	Logger     sharedKernel.Logger
	Director   director.Director
}

func (c AuthController) Handler() gin.IRoutes {
	return c.Router.GET("/saml/auth", func(context *gin.Context) {
		// Generate or extract correlation ID for request tracing
		correlationID := context.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		// Log request start with metadata
		c.Logger.Info(fmt.Sprintf("Handling SAML auth request [correlation_id=%s, method=%s, path=%s, client_ip=%s]", correlationID, context.Request.Method, context.Request.URL.Path, context.ClientIP()))

		// Pass logger to Director
		c.Director.Logger = c.Logger

		// Get root URL
		rootUrl, err := c.Director.GetRootUrl(context.Request)
		if err != nil {
			c.Logger.Failure(fmt.Errorf("failed to get root URL [correlation_id=%s]: %s", correlationID, err.Error()))
			context.JSON(400, gin.H{"message": "Invalid root URL"})
			return
		}

		// Log successful root URL retrieval
		c.Logger.Info(fmt.Sprintf("DEBUG: Retrieved root URL [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		// Get SAML provider
		samlSP, err := c.SamlDomain.GetProvider(rootUrl)
		if err != nil {
			c.Logger.Failure(fmt.Errorf("failed to get SAML provider [correlation_id=%s, root_url=%s]: %s", correlationID, rootUrl, err.Error()))
			context.JSON(400, gin.H{"message": "Invalid SAML provider"})
			return
		}

		// Log successful provider retrieval
		c.Logger.Info(fmt.Sprintf("DEBUG: Retrieved SAML provider [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		// Check session
		session, err := samlSP.Session.GetSession(context.Request)
		if session != nil {
			c.Logger.Info(fmt.Sprintf("Session found, request authenticated [correlation_id=%s, root_url=%s]", correlationID, rootUrl))
			context.Status(200)
			return
		}

		if err == samlsp.ErrNoSession {
			c.Logger.Info(fmt.Sprintf("No session found, unauthorized [correlation_id=%s, root_url=%s]", correlationID, rootUrl))
			context.Status(401)
			return
		}

		// Log unexpected errors during session check
		c.Logger.Failure(fmt.Errorf("unexpected error during session check [correlation_id=%s, root_url=%s]: %s", correlationID, rootUrl, err.Error()))
		context.JSON(500, gin.H{"message": "Internal server error"})
	})
}