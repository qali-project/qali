// Package assembly combines the module HTTP adapters into the single
// generated openapi.ServerInterface. Modules never import each other's
// adapters; only process assembly (cmd/qali and integration tests) does.
package assembly

import (
	identityhttp "github.com/qali-project/qali/internal/identity/adapter/httpapi"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	workspacehttp "github.com/qali-project/qali/internal/workspace/adapter/httpapi"
)

type (
	identityAPI  = identityhttp.Handler
	workspaceAPI = workspacehttp.Handler
)

// api embeds every module handler. The identity handler also embeds
// openapi.Unimplemented, one level deeper, so operations no module
// implements answer 501 and module methods take precedence.
type api struct {
	*identityAPI
	*workspaceAPI
}

// API returns the combined contract implementation.
func API(identity *identityhttp.Handler, workspace *workspacehttp.Handler) openapi.ServerInterface {
	return api{identityAPI: identity, workspaceAPI: workspace}
}
