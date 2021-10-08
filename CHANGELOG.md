# Change Log
## v2.x.x - n2k development 
### Breaking Changes
* Using Keys through ssh-agent is dropped, instead a SSH-keypair per deployment is created, additional public SSH-keys can still be added
* Cluster random id is optional through `var.cluster_append_random_id`
* Cluster random id length can be controlled through `var.cluster_random_id_length`
* Bump Terraform provider for Vultr to `2.4.2`
* Vultr API Key for provisioning can be also specified through `var.deployment_vultr_api_key`
### Changes
* Bump K0s release from `v1.21.3+k0s.0` to `v1.22.2+k0s.1`
* Bump kube-system component versions
* Bump vultr-csi and vultr-ccm to `v0.3.0`
* K0s components can be disabled which is supported since `v1.22` through `var.k0s_disable_components`
* Vultr DNS records can be created optionally if `var.cluster_create_external_dns_hosts` and `var.cluster_external_dns_domain` are set
* Vultr CSI can be disabled through `var.enable_vultr_csi`
* Vultr CCM can be disabled through `var.enable_vultr_ccm`
* Switched `apt` to `apt-get` in `scripts/provisioning.sh`
* Added `apt-get dist-upgrade` to `scripts/provisioning.sh`
* Changed sleep-time to 5s in `safe_apt()`
* Added 30s sleep to `scripts/provisioning.sh` on startup, because there are still some update tasks running when vps becomes available
* `$NODE_ROLE` in `scripts/provisioning.sh` is now passed from terraforms `remote-exec` provisioner, instead of regex-ing hostnames
### Features
* HA Control Plane
* Isolated control plane (Control Plane nodes are not part of the cluster)
* Control Plane and Worker Node firewalls.
* Declarative cluster and component (Vultr CCM, CSI, Calico, etc.) upgrades
* Vultr Cloud Controller Manager and Vultr Container Storage Interface are optional
* K0s manifest deployer support
* External DNS records for ha-plane and nodes when specifing a domain

## [v2.0.0](https://github.com/vultr/terraform-vultr-condor/releases/tag/v2.0.0) (2021-09-03)
### Breaking Changes
* Condor is now based on Mirantis K0s rather than Kubeadm, as such v2 is completely incompatible with previous releases.
### Features
* HA Control Plane
* Isolated control plane(Control Plane nodes are not part of the cluster)
* Control Plane and Worker Node firewalls. 
* Declarative cluster and component(Vultr CCM, CSI, Calico, etc.) upgrades
* K0s manifest deployer support 

## [v1.3.0](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.3.0) (2021-08-25)
### Breaking Changes
* Remove `calico_wireguard` variable - nodes were not properly configured, will need to revisit
* Add `calico_mode` variable - previously defaulted to `vxlan`, is now configurable but defaults to `bird`
### Changes
* Bump K0s release from `v1.21.1+k0s.0` to `v1.21.3+k0s.0`
* Bump kube-system component versions

## [v1.2.3](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.2.3) (2021-07-14)
### Fixes
* Handle dynamic NIC names.

## [v1.2.2](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.2.2) (2021-06-21)
### Fixes
* Fix firewall configuration after Vultr image changes. 

## [v1.2.1](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.2.1) (2021-06-19)
### Changes
* Template Vultr CSI 
* Add Vultr CSI image/version vars
* Add kubeconfig filename tf workspace suffix

## [v1.2.0](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.2.0) (2021-06-12)
### Features
* Support K0s Helm deployments.
### Changes
* Convert module internal K0sctl configuration to HCL from YAML.
### Fixes
* Change Controller/Worker network interfaces from ens3/ens7 to enp1s0/enp6s0 due to Vultr image changes. 

## [v1.1.0](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.1.0) (2021-06-06)
### Features
* Write Kubeconfig locally option.
* Control Plane VLB Firewall. 
### Changes
* Add variable descriptions.
* Lock up cluster firewall, SSH only by default. 
* Docs updates.
### Fixes
* README markdown.

## [v1.0.1](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.0.1) (2021-06-05)
### Fixes
* Remove unused variables from triggers map.

## [v1.0.0](https://github.com/3letteragency/terraform-vultr-k0s/releases/tag/v1.0.0) (2021-06-05)
### First Release
