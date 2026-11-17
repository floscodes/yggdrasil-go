package admin

import "github.com/yggdrasil-network/yggdrasil-go/src/core"

type GetServicesRequest struct{}

type GetServicesResponse struct {
	Services  []core.DiscoveredService
	Discovery core.DiscoveryStatus
}

func (a *AdminSocket) getServicesHandler(_ *GetServicesRequest, res *GetServicesResponse) error {
	res.Services = a.core.GetServices()
	res.Discovery = a.core.GetDiscoveryStatus()
	return nil
}
