package admin

import "github.com/yggdrasil-network/yggdrasil-go/src/core"

type GetServicesRequest struct{}

type GetServicesResponse struct {
	Services []core.DiscoveredService
}

func (a *AdminSocket) getServicesHandler(_ *GetServicesRequest, res *GetServicesResponse) error {
	res.Services = a.core.GetServices()
	return nil
}
