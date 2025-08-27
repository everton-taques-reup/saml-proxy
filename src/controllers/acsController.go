package controllers

import (
	"fmt"
	"github.com/everton-taques-reup/saml-proxy/director"
	"github.com/everton-taques-reup/saml-proxy/domain"
	"github.com/everton-taques-reup/saml-proxy/sharedKernel"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AcsController struct {
	Router     *gin.Engine
	SamlDomain *domain.SamlDomain
	Logger     sharedKernel.Logger
	Director   director.Director
}

func (c AcsController) Handler() gin.IRoutes {
	return c.Router.POST("/saml/acs", func(context *gin.Context) {
		// Generate or extract correlation ID for request tracing
		correlationID := context.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		// Log request start with metadata
		c.Logger.Info(fmt.Sprintf("Handling SAML ACS request [correlation_id=%s, method=%s, path=%s, client_ip=%s]", correlationID, context.Request.Method, context.Request.URL.Path, context.ClientIP()))

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

		// Get middleware provider
		middleware, err := c.SamlDomain.GetProvider(rootUrl)
		if err != nil {
			c.Logger.Failure(fmt.Errorf("failed to get SAML provider [correlation_id=%s, root_url=%s]: %s", correlationID, rootUrl, err.Error()))
			context.JSON(400, gin.H{"message": "Invalid SAML provider"})
			return
		}

		// Log successful provider retrieval
		c.Logger.Info(fmt.Sprintf("DEBUG: Retrieved SAML provider [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		// Log middleware invocation
		c.Logger.Info(fmt.Sprintf("DEBUG: Invoking SAML middleware [correlation_id=%s, root_url=%s]", correlationID, rootUrl))

		// Serve the request
		middleware.ServeHTTP(context.Writer, context.Request)

		// Log successful request completion
		c.Logger.Info(fmt.Sprintf("SAML ACS request processed successfully [correlation_id=%s, root_url=%s]", correlationID, rootUrl))
	})
}