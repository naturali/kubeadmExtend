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
	mRand "math/rand"
	"os"
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
	caEtcdKey      *rsa.PrivateKey
	caEtcdCert     *x509.Certificate

	caKeyBySSH         string
	caCertBySSH        string
	kubectlConfigBySSH string

	CommandSting string
)

func init() {
	flag.StringVar(&KubernetesPath, "KubernetesConfig", "/etc/kubernetes/", "Kubernetes Config Path.")
	flag.StringVar(&caKeyBySSH, "CaKeyBySSH", "", "For Example: k8s-master:/etc/kubernetes/pki/ca.key")
	flag.StringVar(&caCertBySSH, "CaCertBySSH", "", "For Example: k8s-master:/etc/kubernetes/pki/ca.crt")
	flag.StringVar(&kubectlConfigBySSH, "kubectlConfigBySSH", "", "For Example: k8s-node:/etc/kubernetes/kubelet.conf")
	flag.Lookup("stderrthreshold").Value.Set("info")
	flag.Parse()

	CommandSting = `scp -oStrictHostKeyChecking=no %v %v`
}

func exit() {
	glog.Flush()
}

func readCA() {
	glog.Info("Main Init...")
	caKeyFilePath := path.Join(KubernetesPath, "pki", "ca.key")
	caCertFilePath := path.Join(KubernetesPath, "pki", "ca.crt")
	caEtcdKeyFilePath := path.Join(KubernetesPath, "pki", "etcd", "ca.key")
	caEtcdCertFilePath := path.Join(KubernetesPath, "pki", "etcd", "ca.crt")
	caFrontKeyFilePath := path.Join(KubernetesPath, "pki", "front-proxy-ca.key")
	caFrontCertFilePath := path.Join(KubernetesPath, "pki", "front-proxy-ca.crt")

	caKey = tools.ReadKeyFile(caKeyFilePath)
	caCert = tools.ReadCertFile(caCertFilePath)

	if _, err := os.Stat(caFrontKeyFilePath); err == nil {
		caFrontKey = tools.ReadKeyFile(caFrontKeyFilePath)
		caFrontCert = tools.ReadCertFile(caFrontCertFilePath)
	}

	if _, err := os.Stat(caEtcdKeyFilePath); err == nil {
		caEtcdKey = tools.ReadKeyFile(caEtcdKeyFilePath)
		caEtcdCert = tools.ReadCertFile(caEtcdCertFilePath)
	}

}

func frontCertUpdate() {
	if caFrontKey == nil || caFrontCert == nil {
		return
	}

	for _, value := range config.FrontFileBaseNames {
		keyFilePath := path.Join(KubernetesPath, "pki", fmt.Sprint(value, ".key"))
		certFilePath := path.Join(KubernetesPath, "pki", fmt.Sprint(value, ".crt"))

		_, err1 := os.Stat(keyFilePath)
		_, err2 := os.Stat(certFilePath)

		if err1 != nil || err2 != nil {
			return
		}

		key := tools.ReadKeyFile(keyFilePath)
		cert := tools.ReadCertFile(certFilePath)
		tools.VerifyFunc(caFrontCert, cert)
		cert.NotAfter = cert.NotBefore.Add(10 * 365 * 24 * time.Hour)

		glog.Infof("Create... Cert: %+v", value)
		newCart, err := x509.CreateCertificate(rand.Reader, cert, caFrontCert, &key.PublicKey, caFrontKey)
		tools.CheckError(err)

		glog.Infof("Save...   Cert: %+v", value)
		newCartByte := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: newCart})
		err = ioutil.WriteFile(certFilePath, newCartByte, 0644)
		tools.CheckError(err)
	}
	glog.Infof("End...    File: %+v", config.FrontFileBaseNames)

}

func etcdCertUpdate() {
	if caEtcdKey == nil || caEtcdCert == nil {
		return
	}

	for _, value := range config.EtcdFileBaseNames {
		keyFilePath := path.Join(KubernetesPath, "pki", fmt.Sprint(value, ".key"))
		certFilePath := path.Join(KubernetesPath, "pki", fmt.Sprint(value, ".crt"))

		_, err1 := os.Stat(keyFilePath)
		_, err2 := os.Stat(certFilePath)

		if err1 != nil || err2 != nil {
			return
		}

		key := tools.ReadKeyFile(keyFilePath)
		cert := tools.ReadCertFile(certFilePath)
		tools.VerifyFunc(caEtcdCert, cert)
		cert.NotAfter = cert.NotBefore.Add(10 * 365 * 24 * time.Hour)

		glog.Infof("Create... Cert: %+v", value)
		newCart, err := x509.CreateCertificate(rand.Reader, cert, caEtcdCert, &key.PublicKey, caEtcdKey)
		tools.CheckError(err)

		glog.Infof("Save...   Cert: %+v", value)
		newCartByte := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: newCart})
		err = ioutil.WriteFile(certFilePath, newCartByte, 0644)
		tools.CheckError(err)
	}
	glog.Infof("End...    File: %+v", config.EtcdFileBaseNames)

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

func random() int {
	return mRand.New(mRand.NewSource(time.Now().UnixNano())).Int()
}

func updateMinion() {
	caKeyTmp := fmt.Sprintf("/tmp/tmptmp-%v.%v", random(), random())
	caCertTmp := fmt.Sprintf("/tmp/tmptmp-%v.%v", random(), random())
	kubectlConfigTmp := fmt.Sprintf("/tmp/tmptmp-%v.%v", random(), random())

	workMap := map[string]string{
		caKeyBySSH:         caKeyTmp,
		caCertBySSH:        caCertTmp,
		kubectlConfigBySSH: kubectlConfigTmp,
	}

	for sf, lf := range workMap {
		cmd := fmt.Sprintf(CommandSting, sf, lf)
		_, err := tools.Command(cmd)
		if err != nil {
			glog.Fatalf("%v: %v", cmd, err.Error())
		}
	}

	caKey = tools.ReadKeyFile(caKeyTmp)
	caCert = tools.ReadCertFile(caCertTmp)
	kubectlConfig := tools.ReadYamlFileByKubeConf(kubectlConfigTmp)

	key := tools.ReadECKeyByte(tools.UnBase64(tools.GetKeyByKubeConf(kubectlConfig)))
	cert := tools.ReadCertByte(tools.UnBase64(tools.GetCertByKubeConf(kubectlConfig)))
	tools.VerifyFunc(caCert, cert)
	cert.NotAfter = cert.NotBefore.Add(10 * 365 * 24 * time.Hour)

	newCart, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
	tools.CheckError(err)

	newCartByte := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: newCart,
		})
	kubectlConfig.Users[0].User.ClientCertificateData = base64.StdEncoding.EncodeToString(newCartByte)
	tools.SaveYamlFileByKubeConf(kubectlConfigTmp, kubectlConfig)

	cmd := fmt.Sprintf(CommandSting, kubectlConfigTmp, kubectlConfigBySSH)
	_, err = tools.Command(cmd)
	if err != nil {
		glog.Fatalf("%v: %v", cmd, err.Error())
	}

	for _, lf := range workMap {
		os.Remove(lf)
	}

}

func main() {
	if caKeyBySSH != "" && caCertBySSH != "" && kubectlConfigBySSH != "" {
		updateMinion()
	} else {
		readCA()
		etcdCertUpdate()
		frontCertUpdate()
		kubeAPICertUpdate()
	}
}
