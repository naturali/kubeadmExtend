package tools

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// KubeConf Is Struct
type KubeConf struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// ReadYamlFileByKubeConf Is Func
func ReadYamlFileByKubeConf(path string) (config KubeConf) {
	body, err := ioutil.ReadFile(path)
	CheckError(err)

	err = yaml.Unmarshal(body, &config)
	CheckError(err)

	return
}

// SaveYamlFileByKubeConf Is Func
func SaveYamlFileByKubeConf(path string, data KubeConf) {
	dataByte, err := yaml.Marshal(data)
	CheckError(err)
	err = ioutil.WriteFile(path, dataByte, 0600)
	CheckError(err)
}

// GetKeyByKubeConf Is Func
func GetKeyByKubeConf(config KubeConf) string {
	// if len(config.Users) != 1 {
	// 	CheckError(errors.New("In Kubernetes Yaml Config File, Len(Users) != 1"))
	// }
	return config.Users[0].User.ClientKeyData
}

// GetCertByKubeConf Is Func
func GetCertByKubeConf(config KubeConf) string {
	// if len(config.Users) != 1 {
	// 	CheckError(errors.New("In Kubernetes Yaml Config File, Len(Users) != 1"))
	// }
	return config.Users[0].User.ClientCertificateData
}
