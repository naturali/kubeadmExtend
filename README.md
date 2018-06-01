# kubeadmExtend


Extend Kubernetes Cert NotAfter Time.

```
systemctl stop docker && systemctl stop kubelet
cp -a /etc/kubernetes /etc/kubernetes_$(date +'%Y%m%d%H%M%S')
dep ensure -v
go run cmd/kubeadmExtend/main.go
systemctl start docker && systemctl start kubelet
```