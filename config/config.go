package config

// Vars
var (
	ConfigFileBaseNames []string
	SSLFileBaseNames    []string
)

func init() {
	SSLFileBaseNames = []string{
		"apiserver", "apiserver-kubelet-client",
	}
	ConfigFileBaseNames = []string{
		"admin", "controller-manager", "kubelet", "scheduler",
	}
}
