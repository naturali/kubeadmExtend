# kubeadmExtend


Extend Kubernetes Cert NotAfter Time.

```
.
├── admin.conf
├── controller-manager.conf
├── kubelet.conf
├── manifests
│   ├── kube-apiserver.yaml
│   ├── kube-controller-manager.yaml
│   └── kube-scheduler.yaml
├── pki
│   ├── apiserver-etcd-client.crt
│   ├── apiserver-etcd-client.key
│   ├── apiserver-kubelet-client.crt
│   ├── apiserver-kubelet-client.key
│   ├── apiserver.crt
│   ├── apiserver.key
│   ├── ca.crt
│   ├── ca.key
│   ├── etcd
│   │   ├── ca.crt
│   │   ├── ca.key
│   │   ├── healthcheck-client.crt
│   │   ├── healthcheck-client.key
│   │   ├── peer.crt
│   │   ├── peer.key
│   │   ├── server.crt
│   │   └── server.key
│   ├── front-proxy-ca.crt
│   ├── front-proxy-ca.key
│   ├── front-proxy-client.crt
│   ├── front-proxy-client.key
│   ├── sa.key
│   └── sa.pub
└── scheduler.conf
```

```
systemctl stop docker && systemctl stop kubelet
cp -a /etc/kubernetes /etc/kubernetes_$(date +'%Y%m%d%H%M%S')
dep ensure -v
go run cmd/kubeadmExtend/main.go
systemctl start docker && systemctl start kubelet
```