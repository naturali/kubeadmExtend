package config

// Vars
var (
	SSLFileBaseNames    []string
	EtcdFileBaseNames   []string
	FrontFileBaseNames  []string
	ConfigFileBaseNames []string
)

func init() {
	SSLFileBaseNames = []string{
		"apiserver", "apiserver-kubelet-client",
	}
	EtcdFileBaseNames = []string{
		"apiserver-etcd-client", "etcd/healthcheck-client", "etcd/peer", "etcd/server",
	}
	FrontFileBaseNames = []string{
		"front-proxy-client",
	}
	ConfigFileBaseNames = []string{
		"admin", "controller-manager", "kubelet", "scheduler",
	}

}
