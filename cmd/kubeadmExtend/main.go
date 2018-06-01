package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"path"
	"time"

	"github.com/golang/glog"
	"github.com/naturali/kubeadmExtend/config"
	"github.com/naturali/kubeadmExtend/tools"
)

// Var
var (
	KubernetesPath string
	caKey          *rsa.PrivateKey
	caCert         *x509.Certificate
	caFrontKey     *rsa.PrivateKey
	caFrontCert    *x509.Certificate
)

func init() {
	flag.StringVar(&KubernetesPath, "KubernetesConfig", "/etc/kubernetes/", "Kubernetes Config Path.")
	flag.Lookup("stderrthreshold").Value.Set("info")
	flag.Parse()
}

func exit() {
	glog.Flush()
}

func readCA() {
	glog.Info("Main Init...")
	caKeyFilePath := path.Join(KubernetesPath, "pki", "ca.key")
	caCertFilePath := path.Join(KubernetesPath, "pki", "ca.crt")
	caFrontKeyFilePath := path.Join(KubernetesPath, "pki", "front-proxy-ca.key")
	caFrontCertFilePath := path.Join(KubernetesPath, "pki", "front-proxy-ca.crt")

	caKey = tools.ReadKeyFile(caKeyFilePath)
	caCert = tools.ReadCertFile(caCertFilePath)
	caFrontKey = tools.ReadKeyFile(caFrontKeyFilePath)
	caFrontCert = tools.ReadCertFile(caFrontCertFilePath)
}

func kubeAPICertUpdate() {
	for _, value := range config.SSLFileBaseNames {
		glog.Infof("Start...  File: %+v", value)
		keyFilePath := path.Join(KubernetesPath, "pki", fmt.Sprint(value, ".key"))
		certFilePath := path.Join(KubernetesPath, "pki", fmt.Sprint(value, ".crt"))

		key := tools.ReadKeyFile(keyFilePath)
		cert := tools.ReadCertFile(certFilePath)
		tools.VerifyFunc(caCert, cert)
		cert.NotAfter = cert.NotBefore.Add(10 * 365 * 24 * time.Hour)

		glog.Infof("Create... Cert: %+v", value)
		newCart, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
		tools.CheckError(err)

		glog.Infof("Save...   Cert: %+v", value)
		newCartByte := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: newCart})
		err = ioutil.WriteFile(certFilePath, newCartByte, 0644)
		tools.CheckError(err)
	}
	glog.Infof("End...    File: %+v", config.SSLFileBaseNames)

	for _, value := range config.ConfigFileBaseNames {
		glog.Infof("Start...  File: %+v", value)
		filePath := path.Join(KubernetesPath, fmt.Sprint(value, ".conf"))
		yamlConfig := tools.ReadYamlFileByKubeConf(filePath)

		key := tools.ReadKeyByte(tools.UnBase64(tools.GetKeyByKubeConf(yamlConfig)))
		cert := tools.ReadCertByte(tools.UnBase64(tools.GetCertByKubeConf(yamlConfig)))
		tools.VerifyFunc(caCert, cert)
		cert.NotAfter = cert.NotBefore.Add(10 * 365 * 24 * time.Hour)

		glog.Infof("Create... Cert: %+v", value)
		newCart, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
		tools.CheckError(err)

		glog.Infof("Save...   Cert: %+v", value)
		newCartByte := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: newCart})
		yamlConfig.Users[0].User.ClientCertificateData = base64.StdEncoding.EncodeToString(newCartByte)
		tools.SaveYamlFileByKubeConf(filePath, yamlConfig)
	}
	glog.Infof("End...    File: %+v", config.ConfigFileBaseNames)
}

func main() {
	readCA()
	kubeAPICertUpdate()
}
