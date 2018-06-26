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

```
NAME                                            READY     STATUS    RESTARTS   AGE
coredns-7997f8864c-dsqtc                        1/1       Running   1          6y
coredns-7997f8864c-fhkh2                        1/1       Running   1          6y
etcd-localhost.localdomain                      1/1       Running   2          6y
kube-apiserver-localhost.localdomain            1/1       Running   2          6y
kube-controller-manager-localhost.localdomain   1/1       Running   2          6y
kube-flannel-ds-z9hd8                           1/1       Running   2          6y
kube-proxy-88f6q                                1/1       Running   1          6y
kube-scheduler-localhost.localdomain            1/1       Running   2          6y
```

```
go run cmd/kubeadmExtend/main.go \
    --CaKeyBySSH=k8s_master:/etc/kubernetes/pki/ca.key \
    --CaCertBySSH=k8s_master:/etc/kubernetes/pki/ca.crt \
    --kubectlConfigBySSH=k8s_node01:/etc/kubernetes/kubelet.conf

ssh k8s_node01 "systemctl restart kubelet"
```
