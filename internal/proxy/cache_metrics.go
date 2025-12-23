package proxy

import (
	"expvar"
	"sync"
)

var registerProxyVarsOnce sync.Once

func registerProxyCacheVars() {
	registerProxyVarsOnce.Do(func() {
		m := expvar.NewMap("deputy_proxy_cache")
		m.Set("osv", expvar.Func(func() any { return defaultOSVCache.Stats() }))
		m.Set("license", expvar.Func(func() any { return defaultLicenseCache.Stats() }))
	})
}
