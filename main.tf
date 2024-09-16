terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = ">=2.4.2"
    }
  }
}

provider "vultr" {
  api_key = var.deployment_vultr_api_key
}

locals {
  enable_vultr_extensions           = (var.enable_vultr_ccm || var.enable_vultr_csi) && length(var.cluster_vultr_api_key) > 0
  cluster_name                      = var.cluster_append_random_id == true  ? "${var.cluster_name}-${random_id.cluster.hex}" : var.cluster_name

  public_keys                       = concat([vultr_ssh_key.instance.id], vultr_ssh_key.extra_public_keys.*.id)

  k0sctl_install_flags_enable_ccm   = tostring(var.enable_vultr_ccm && (length(var.cluster_vultr_api_key) > 0))
  k0sctl_install_flags_disable_comp = length(var.k0s_disable_components) > 0 ? join(", ", var.k0s_disable_components) : false

  k0sctl_controllers = [
    for host in vultr_instance.control_plane :
    {
      role = "controller"
      installFlags = [
        "--enable-cloud-provider=${local.k0sctl_install_flags_enable_ccm}",
        length(var.k0s_disable_components) > 0 ? "--disable-components ${local.k0sctl_install_flags_disable_comp}" : ""
      ]
      privateAddress = host.internal_ip
      ssh = {
        address = host.main_ip
        user    = "root"
        port    = 22
        keyPath = local_file.private_key_root.filename
      }
    }
  ]
  k0sctl_workers = [
    for host in vultr_instance.worker :
    {
      role = "worker"
      installFlags = [
        "--enable-cloud-provider=${local.k0sctl_install_flags_enable_ccm}"
      ]
      privateAddress = host.internal_ip
      ssh = {
        address = host.main_ip
        user    = "root"
        port    = 22
        keyPath = local_file.private_key_root.filename
      }
    }
  ]

  # only use loadbalancer ip if needed
  ingress_ip = var.controller_count == 1  ? vultr_instance.control_plane[0].main_ip : vultr_load_balancer.control_plane_ha[0].ipv4

  k0s_api_sans = (var.cluster_create_external_dns_hosts && length(var.cluster_external_dns_domain) > 0) ? concat([ vultr_load_balancer.control_plane_ha[0].ipv4 ], [ format("%s.%s", vultr_dns_record.control_plane_ha_dns_record[0].name, vultr_dns_record.control_plane_ha_dns_record[0].domain) ]) : [ local.ingress_ip ]
  /* k0s_depends_on = var.controller_count == 1  ? [ vultr_instance.control_plane, vultr_instance.worker, local_file.k0sctl_conf ] : [ vultr_load_balancer.control_plane_ha , vultr_instance.control_plane, vultr_instance.worker, local_file.k0sctl_conf ] */

  k0sctl_conf = {
    apiVersion = "k0sctl.k0sproject.io/v1beta1"
    kind       = "Cluster"
    metadata = {
      name = local.cluster_name
    }
    spec = {
      hosts = concat(local.k0sctl_controllers, local.k0sctl_workers)
      k0s = {
        version = var.k0s_version
        config = {
          apiVersion = "k0s.k0sproject.io/v1beta1"
          kind       = "Cluster"
          metadata = {
            name = local.cluster_name
          }
          spec = {
            extensions = {
              helm = {
                repositories = var.helm_repositories
                charts       = var.helm_charts
              }
            }
            telemetry = {
              enabled = false
            }
            api = {
              port            = 6443
              k0sApiPort      = 9443
              externalAddress = local.ingress_ip
              address         = local.ingress_ip
              # sans = [ local.ingress_ip ]
              sans = local.k0s_api_sans
            }
            network = {
              podCIDR     = var.pod_cidr
              serviceCIDR = var.svc_cidr
              "provider"  = "calico"
              calico = {
                mode = var.calico_mode
              }
            }
            podSecurityPolicy = {
              defaultPolicy = var.pod_sec_policy
            }
            images = {
              konnectivity = {
                image   = "us.gcr.io/k8s-artifacts-prod/kas-network-proxy/proxy-agent"
                version = var.konnectivity_version
              }
              metricsserver = {
                image   = "gcr.io/k8s-staging-metrics-server/metrics-server"
                version = var.metrics_server_version
              }
              kubeproxy = {
                image   = "k8s.gcr.io/kube-proxy"
                version = var.kube_proxy_version
              }
              coredns = {
                image   = "docker.io/coredns/coredns"
                version = var.core_dns_version
              }
              calico = {
                cni = {
                  image   = "calico/cni"
                  version = var.calico_cni_version
                }
                node = {
                  image   = "calico/node"
                  version = var.calico_node_version
                }
                kubecontrollers = {
                  image   = "calico/kube-controllers"
                  version = var.calico_kubecontrollers_version
                }
              }
            }
          }
        }
      }
    }
  }

  config_sha256sum = sha256(tostring(jsonencode(local.k0sctl_conf)))
}

data "vultr_os" "cluster" {
  filter {
    name   = "name"
    values = [var.cluster_os]
  }
}

resource "random_id" "cluster" {
  byte_length = var.cluster_random_id_length
}

resource "tls_private_key" "root_tls_key" {
  algorithm   = "RSA"
  rsa_bits = 2048
}

resource "vultr_ssh_key" "instance" {
  name                  = "Provisioner public key for k0s cluster ${local.cluster_name}"
  ssh_key               = tls_private_key.root_tls_key.public_key_openssh
}

resource "local_file" "private_key_root" {
  content         = tls_private_key.root_tls_key.private_key_pem
  filename        = "${abspath(path.root)}/.ssh/${local.cluster_name}_${lower(tls_private_key.root_tls_key.algorithm)}"
  file_permission = "0600"
}

resource "local_file" "public_key_root" {
  content         = tls_private_key.root_tls_key.public_key_pem
  filename        = "${abspath(path.root)}/.ssh/${local.cluster_name}_${lower(tls_private_key.root_tls_key.algorithm)}.pub"
  file_permission = "0600"
}

resource "vultr_ssh_key" "extra_public_keys" {
  count   = length(var.extra_public_keys)
  name    = "Public key for k0s cluster ${random_id.cluster.hex}"
  ssh_key = var.extra_public_keys[count.index]
}

resource "vultr_private_network" "cluster" {
  description    = "Private Network for k0s cluster ${random_id.cluster.hex}"
  region         = var.region
  v4_subnet      = element(split("/", var.node_subnet), 0)
  v4_subnet_mask = element(split("/", var.node_subnet), 1)
}

resource "vultr_load_balancer" "control_plane_ha" {
  # disable if only one controller 
  count = var.controller_count - 1
  region              = var.region
  label               = "HA Control Plane Load Balancer for k0s cluster ${random_id.cluster.hex}"
  balancing_algorithm = var.ha_lb_algorithm
  private_network     = vultr_private_network.cluster.id

  forwarding_rules {
    frontend_protocol = "tcp"
    frontend_port     = 6443
    backend_protocol  = "tcp"
    backend_port      = 6443
  }

  dynamic "firewall_rules" {
    for_each = vultr_instance.worker
    iterator = instance
    content {
      port    = 6443
      ip_type = "v4"
      source  = "${instance.value["main_ip"]}/32"
    }
  }

  forwarding_rules {
    frontend_protocol = "tcp"
    frontend_port     = 8132
    backend_protocol  = "tcp"
    backend_port      = 8132
  }

  dynamic "firewall_rules" {
    for_each = vultr_instance.worker
    iterator = instance
    content {
      port    = 8132
      ip_type = "v4"
      source  = "${instance.value["main_ip"]}/32"
    }
  }

  forwarding_rules {
    frontend_protocol = "tcp"
    frontend_port     = 8133
    backend_protocol  = "tcp"
    backend_port      = 8133
  }

  dynamic "firewall_rules" {
    for_each = vultr_instance.worker
    iterator = instance
    content {
      port    = 8133
      ip_type = "v4"
      source  = "${instance.value["main_ip"]}/32"
    }
  }

  forwarding_rules {
    frontend_protocol = "tcp"
    frontend_port     = 9443
    backend_protocol  = "tcp"
    backend_port      = 9443
  }

  dynamic "firewall_rules" {
    for_each = vultr_instance.control_plane
    iterator = instance
    content {
      port    = 9443
      ip_type = "v4"
      source  = "${instance.value["main_ip"]}/32"
    }
  }

  dynamic "firewall_rules" {
    for_each = var.control_plane_firewall_rules
    iterator = rule
    content {
      port    = rule.value["port"]
      ip_type = rule.value["ip_type"]
      source  = rule.value["source"]
    }
  }

  health_check {
    port                = "6443"
    protocol            = "tcp"
    response_timeout    = var.ha_lb_health_response_timeout
    unhealthy_threshold = var.ha_lb_health_unhealthy_threshold
    check_interval      = var.ha_lb_health_check_interval
    healthy_threshold   = var.ha_lb_health_healthy_threshold
  }

  attached_instances = vultr_instance.control_plane.*.id
}

resource "vultr_firewall_group" "cluster" {
  description = "Firewall group for k0s cluster ${random_id.cluster.hex}"
}

resource "vultr_firewall_rule" "ssh" {
  count             = var.allow_ssh ? 1 : 0
  firewall_group_id = vultr_firewall_group.cluster.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
  notes             = "Allow SSH to all cluster nodes globally."
}

resource "vultr_firewall_rule" "k8s" {
  firewall_group_id = vultr_firewall_group.cluster.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "6443"
  notes             = "Allow k8s port, needed for instance created check of terraform"
}

resource "vultr_firewall_rule" "k9s_api" {
  firewall_group_id = vultr_firewall_group.cluster.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "9443"
  notes             = "Allow k9s port, needed for instance created check of terraform"
}

resource "vultr_firewall_rule" "unknown_api" {
  firewall_group_id = vultr_firewall_group.cluster.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "8132"
  notes             = "Allow unknown port, needed for instance created check of terraform?"
}

resource "vultr_firewall_rule" "ftapi" {
  count             = var.allow_ftapi ? 1 : 0
  firewall_group_id = vultr_firewall_group.cluster.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "30000"
  notes             = "Allow freqtrade API to all cluster nodes globally."
}

resource "vultr_firewall_rule" "etcd" {
  count             = var.controller_count
  firewall_group_id = vultr_firewall_group.cluster.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = vultr_instance.control_plane[count.index].main_ip
  subnet_size       = 32
  port              = "2380"
  notes             = "Allow Etcd for Control Plane members."
}

resource "vultr_instance" "control_plane" {
  depends_on = [
    vultr_private_network.cluster
  ]
  count               = var.controller_count
  plan                = var.controller_plan
  hostname            = "${local.cluster_name}-ctr-${format("%02d", count.index + 1)}"
  label               = "${local.cluster_name}-ctr-${format("%02d", count.index + 1)}"
  region              = var.region
  os_id               = data.vultr_os.cluster.id
  firewall_group_id   = vultr_firewall_group.cluster.id
  private_network_ids = [vultr_private_network.cluster.id]
  ssh_key_ids         = local.public_keys
  enable_ipv6         = var.enable_ipv6
  activation_email    = var.activation_email
  ddos_protection     = var.ddos_protection
  tag                 = var.tag

  connection {
    type = "ssh"
    timeout = "10m"
    user = "root"
    host = self.main_ip
    private_key = tls_private_key.root_tls_key.private_key_pem
  }

  provisioner "file" {
    source      = "${path.module}/scripts/provision.sh"
    destination = "/tmp/provision.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/provision.sh",
      "export NODE_ROLE=controller",
      "/tmp/provision.sh ${self.internal_ip}",
      "rm -f /tmp/provision.sh"
    ]
  }
}

resource "vultr_instance" "worker" {
  depends_on = [
    vultr_private_network.cluster
  ]
  count               = var.worker_count
  plan                = var.worker_plan
  hostname            = "${local.cluster_name}-wrk-${format("%02d", count.index + 1)}"
  label               = "${local.cluster_name}-wrk-${format("%02d", count.index + 1)}"
  region              = var.region
  os_id               = data.vultr_os.cluster.id
  firewall_group_id   = vultr_firewall_group.cluster.id
  private_network_ids = [vultr_private_network.cluster.id]
  ssh_key_ids         = local.public_keys
  enable_ipv6         = var.enable_ipv6
  activation_email    = var.activation_email
  ddos_protection     = var.ddos_protection
  tag                 = var.tag

  connection {
    type = "ssh"
    timeout = "10m"
    user = "root"
    private_key = tls_private_key.root_tls_key.private_key_pem
    host = self.main_ip
  }

  provisioner "file" {
    source      = "${path.module}/scripts/provision.sh"
    destination = "/tmp/provision.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/provision.sh",
      "export NODE_ROLE=worker",
      "/tmp/provision.sh ${self.internal_ip}",
      "rm -f /tmp/provision.sh"
    ]
  }
}

resource "vultr_dns_record" "control_plane_dns_records" {
    count             = (var.cluster_create_external_dns_hosts && length(var.cluster_external_dns_domain) > 0 && length(vultr_instance.control_plane) > 0) ? length(vultr_instance.control_plane) : 0
    domain            = var.cluster_external_dns_domain
    name              = vultr_instance.control_plane[count.index].hostname
    type              = "A"
    data              = vultr_instance.control_plane[count.index].main_ip
    ttl               = 120 # don't go below 120, not accepted!
}

resource "vultr_dns_record" "worker_dns_records" {
    count             = (var.cluster_create_external_dns_hosts && length(var.cluster_external_dns_domain) > 0 && length(vultr_instance.worker) > 0) ? length(vultr_instance.worker) : 0
    domain            = var.cluster_external_dns_domain
    name              = vultr_instance.worker[count.index].hostname
    type              = "A"
    data              = vultr_instance.worker[count.index].main_ip
    ttl               = 120
}

resource "vultr_dns_record" "control_plane_ha_dns_record" {
    count             = (var.cluster_create_external_dns_hosts && length(var.cluster_external_dns_domain) > 0) ? 1 : 0
    domain            = var.cluster_external_dns_domain
    name              = local.cluster_name
    type              = "A"
    data              = vultr_load_balancer.control_plane_ha[0].ipv4
    ttl               = 120
}


resource "local_file" "k0sctl_conf" {
  content         = yamlencode(local.k0sctl_conf)
  filename        = "${abspath(path.root)}/k0sctl.yaml"
  file_permission = "0600"
}

resource "null_resource" "k0s" {
  depends_on = [ vultr_instance.control_plane, vultr_instance.worker, local_file.k0sctl_conf ]
  triggers = {
    controller_count = var.controller_count
    worker_count     = var.worker_count
    config           = local.config_sha256sum
  }

  provisioner "local-exec" {
    command ="k0sctl apply --disable-telemetry"
  }
}
resource "null_resource" "vultr_extensions" {
  count = local.enable_vultr_extensions == true ? var.controller_count : 0

  triggers = {
    api_key     = var.cluster_vultr_api_key
    ccm_version = var.vultr_ccm_version
    csi_version = var.vultr_csi_version
  }

  connection {
    type = "ssh"
    timeout = "10m"
    user = "root"
    host = vultr_instance.control_plane[count.index].main_ip
    private_key = tls_private_key.root_tls_key.private_key_pem

  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /var/lib/k0s/manifests/vultr"
    ]
  }

}

resource "null_resource" "vultr_ccm_extension" {
  count = var.enable_vultr_ccm == true ? var.controller_count : 0

  depends_on = [
    null_resource.vultr_extensions
  ]

  triggers = {
    api_key     = var.cluster_vultr_api_key
    ccm_version = var.vultr_ccm_version
  }

  connection {
    type = "ssh"
    timeout = "10m"
    user = "root"
    host = vultr_instance.control_plane[count.index].main_ip
    private_key = tls_private_key.root_tls_key.private_key_pem

  }

  provisioner "file" {
    content     = <<-EOT
      apiVersion: v1
      kind: Secret
      metadata:
        name: vultr-ccm
        namespace: kube-system
      stringData:
        api-key: "${var.cluster_vultr_api_key}"
        region: "${var.region}"
      ---
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: vultr-ccm
        namespace: kube-system
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRole
      metadata:
        annotations:
          rbac.authorization.kubernetes.io/autoupdate: "true"
        name: system:vultr-ccm
      rules:
        - apiGroups:
            - ""
          resources:
            - events
          verbs:
            - create
            - patch
            - update
        - apiGroups:
            - ""
          resources:
            - nodes
          verbs:
            - '*'
        - apiGroups:
            - ""
          resources:
            - nodes/status
          verbs:
            - patch
        - apiGroups:
            - ""
          resources:
            - services
          verbs:
            - list
            - patch
            - update
            - watch
        - apiGroups:
            - ""
          resources:
            - services/status
          verbs:
            - list
            - patch
            - update
            - watch
        - apiGroups:
            - ""
          resources:
            - serviceaccounts
          verbs:
            - create
            - get
        - apiGroups:
            - ""
          resources:
            - persistentvolumes
          verbs:
            - get
            - list
            - update
            - watch
        - apiGroups:
            - ""
          resources:
            - endpoints
          verbs:
            - create
            - get
            - list
            - watch
            - update
        - apiGroups:
            - coordination.k8s.io
          resources:
            - leases
          verbs:
            - create
            - get
            - list
            - watch
            - update
        - apiGroups:
            - ""
          resources:
            - secrets
          verbs:
            - get
            - list
            - watch
      ---
      kind: ClusterRoleBinding
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: system:vultr-ccm
      roleRef:
        apiGroup: rbac.authorization.k8s.io
        kind: ClusterRole
        name: system:vultr-ccm
      subjects:
        - kind: ServiceAccount
          name: vultr-ccm
          namespace: kube-system
      ---
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: vultr-ccm
        labels:
          app: vultr-ccm
        namespace: kube-system
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: vultr-ccm
        template:
          metadata:
            labels:
              app: vultr-ccm
          spec:
            serviceAccountName: vultr-ccm
            tolerations:
              - key: "CriticalAddonsOnly"
                operator: "Exists"
              - key: "node.cloudprovider.kubernetes.io/uninitialized"
                value: "true"
                effect: "NoSchedule"
              - key: node.kubernetes.io/not-ready
                operator: Exists
                effect: NoSchedule
              - key: node.kubernetes.io/unreachable
                operator: Exists
                effect: NoSchedule
            hostNetwork: true
            containers:
              - image: vultr/vultr-cloud-controller-manager:${var.vultr_ccm_version}
                imagePullPolicy: Always
                name: vultr-cloud-controller-manager
                command:
                  - "/vultr-cloud-controller-manager"
                  - "--cloud-provider=vultr"
                  - "--allow-untagged-cloud=true"
                  - "--authentication-skip-lookup=true"
                  - "--v=3"
                env:
                  - name: VULTR_API_KEY
                    valueFrom:
                      secretKeyRef:
                        name: vultr-ccm
                        key: api-key
    EOT
    destination = "/var/lib/k0s/manifests/vultr/vultr-ccm-${var.vultr_ccm_version}.yaml"
  }
}

resource "null_resource" "vultr_csi_extension" {
  count = var.enable_vultr_csi ? var.controller_count : 0

  depends_on = [
    null_resource.vultr_extensions
  ]

  triggers = {
    api_key     = var.cluster_vultr_api_key
    csi_version = var.vultr_csi_version
    csi_provisioner_version = var.csi_provisioner_version
    csi_attacher_version = var.csi_attacher_version
    csi_node_driver_registrar_version = var.csi_node_driver_registrar_version
  }

  connection {
    type = "ssh"
    timeout = "10m"
    user = "root"
    host = vultr_instance.control_plane[count.index].main_ip
    private_key = tls_private_key.root_tls_key.private_key_pem
  }

  provisioner "file" {
    content     = <<-EOT
      apiVersion: v1
      kind: Secret
      metadata:
        name: vultr-csi
        namespace: kube-system
      stringData:
        api-key: "${var.cluster_vultr_api_key}"
      ---
      ####################
      ### Storage Classes
      ####################
      apiVersion: storage.k8s.io/v1beta1
      kind: CSIDriver
      metadata:
        name: block.csi.vultr.com
      spec:
        attachRequired: true
        podInfoOnMount: true

      ---
      kind: StorageClass
      apiVersion: storage.k8s.io/v1
      metadata:
        name: vultr-block-storage
        namespace: kube-system
        annotations:
          storageclass.kubernetes.io/is-default-class: "true"
      provisioner: block.csi.vultr.com

      ---
      kind: StorageClass
      apiVersion: storage.k8s.io/v1
      metadata:
        name: vultr-block-storage-retain
        namespace: kube-system
      provisioner: block.csi.vultr.com
      reclaimPolicy: Retain

      ###################
      ### CSI Controller
      ###################
      ---
      kind: StatefulSet
      apiVersion: apps/v1
      metadata:
        name: csi-vultr-controller
        namespace: kube-system
      spec:
        serviceName: "csi-vultr"
        replicas: 1
        selector:
          matchLabels:
            app: csi-vultr-controller
        template:
          metadata:
            labels:
              app: csi-vultr-controller
              role: csi-vultr
          spec:
            serviceAccountName: csi-vultr-controller-sa
            containers:
              - name: csi-provisioner
                image: k8s.gcr.io/sig-storage/csi-provisioner:${var.csi_provisioner_version}
                args:
                  - "--volume-name-prefix=pvc"
                  - "--volume-name-uuid-length=16"
                  - "--csi-address=$(ADDRESS)"
                  - "--v=5"
                  - "--default-fstype=ext4"
                env:
                  - name: ADDRESS
                    value: /var/lib/csi/sockets/pluginproxy/csi.sock
                imagePullPolicy: "Always"
                volumeMounts:
                  - name: socket-dir
                    mountPath: /var/lib/csi/sockets/pluginproxy/
              - name: csi-attacher
                image: k8s.gcr.io/sig-storage/csi-attacher:${var.csi_attacher_version}
                args:
                  - "--v=5"
                  - "--csi-address=$(ADDRESS)"
                env:
                  - name: ADDRESS
                    value: /var/lib/csi/sockets/pluginproxy/csi.sock
                imagePullPolicy: "Always"
                volumeMounts:
                  - name: socket-dir
                    mountPath: /var/lib/csi/sockets/pluginproxy/
              - name: csi-vultr-plugin
                image: ${var.vultr_csi_image}:${var.vultr_csi_version}
                args:
                  - "--endpoint=$(CSI_ENDPOINT)"
                  - "--token=$(VULTR_API_KEY)"
                env:
                  - name: CSI_ENDPOINT
                    value: unix:///var/lib/csi/sockets/pluginproxy/csi.sock
                  - name: VULTR_API_KEY
                    valueFrom:
                      secretKeyRef:
                        name: vultr-csi
                        key: api-key
                imagePullPolicy: "Always"
                volumeMounts:
                  - name: socket-dir
                    mountPath: /var/lib/csi/sockets/pluginproxy/
            volumes:
              - name: socket-dir
                emptyDir: { }

      ---
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: csi-vultr-controller-sa
        namespace: kube-system

      ## Attacher Role + Binding
      ---
      kind: ClusterRole
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: csi-vultr-attacher-role
        namespace: kube-system
      rules:
        - apiGroups: [ "" ]
          resources: [ "persistentvolumes" ]
          verbs: [ "get", "list", "watch", "update", "patch" ]
        - apiGroups: [ "" ]
          resources: [ "nodes" ]
          verbs: [ "get", "list", "watch" ]
        - apiGroups: [ "storage.k8s.io" ]
          resources: [ "csinodes" ]
          verbs: [ "get", "list", "watch" ]
        - apiGroups: [ "storage.k8s.io" ]
          resources: [ "volumeattachments" ]
          verbs: [ "get", "list", "watch", "update", "patch" ]
        - apiGroups: [ "storage.k8s.io" ]
          resources: [ "volumeattachments/status" ]
          verbs: [ "patch" ]

      ---
      kind: ClusterRoleBinding
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: csi-controller-attacher-binding
        namespace: kube-system
      subjects:
        - kind: ServiceAccount
          name: csi-vultr-controller-sa
          namespace: kube-system
      roleRef:
        kind: ClusterRole
        name: csi-vultr-attacher-role
        apiGroup: rbac.authorization.k8s.io

      ## Provisioner Role + Binding
      ---
      kind: ClusterRole
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: csi-vultr-provisioner-role
        namespace: kube-system
      rules:
        - apiGroups: [ "" ]
          resources: [ "secrets" ]
          verbs: [ "get", "list" ]
        - apiGroups: [ "" ]
          resources: [ "persistentvolumes" ]
          verbs: [ "get", "list", "watch", "create", "delete" ]
        - apiGroups: [ "" ]
          resources: [ "persistentvolumeclaims" ]
          verbs: [ "get", "list", "watch", "update" ]
        - apiGroups: [ "storage.k8s.io" ]
          resources: [ "storageclasses" ]
          verbs: [ "get", "list", "watch" ]
        - apiGroups: [ "storage.k8s.io" ]
          resources: [ "csinodes" ]
          verbs: [ "get", "list", "watch" ]
        - apiGroups: [ "" ]
          resources: [ "events" ]
          verbs: [ "list", "watch", "create", "update", "patch" ]
        - apiGroups: [ "" ]
          resources: [ "nodes" ]
          verbs: [ "get", "list", "watch" ]
        - apiGroups: [ "storage.k8s.io" ]
          resources: [ "volumeattachments" ]
          verbs: [ "get", "list", "watch" ]

      ---
      kind: ClusterRoleBinding
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: csi-controller-provisioner-binding
        namespace: kube-system
      subjects:
        - kind: ServiceAccount
          name: csi-vultr-controller-sa
          namespace: kube-system
      roleRef:
        kind: ClusterRole
        name: csi-vultr-provisioner-role
        apiGroup: rbac.authorization.k8s.io


      ############
      ## CSI Node
      ############
      ---
      kind: DaemonSet
      apiVersion: apps/v1
      metadata:
        name: csi-vultr-node
        namespace: kube-system
      spec:
        selector:
          matchLabels:
            app: csi-vultr-node
        template:
          metadata:
            labels:
              app: csi-vultr-node
              role: csi-vultr
          spec:
            serviceAccountName: csi-vultr-node-sa
            hostNetwork: true
            containers:
              - name: driver-registrar
                image: k8s.gcr.io/sig-storage/csi-node-driver-registrar:${var.csi_node_driver_registrar_version}
                args:
                  - "--v=5"
                  - "--csi-address=$(ADDRESS)"
                  - "--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)"
                env:
                  - name: ADDRESS
                    value: /csi/csi.sock
                  - name: DRIVER_REG_SOCK_PATH
                    value: /var/lib/k0s/kubelet/plugins/block.csi.vultr.com/csi.sock
                  - name: KUBE_NODE_NAME
                    valueFrom:
                      fieldRef:
                        fieldPath: spec.nodeName
                volumeMounts:
                  - name: plugin-dir
                    mountPath: /csi/
                  - name: registration-dir
                    mountPath: /registration/
              - name: csi-vultr-plugin
                image: ${var.vultr_csi_image}:${var.vultr_csi_version}
                args:
                  - "--endpoint=$(CSI_ENDPOINT)"
                env:
                  - name: CSI_ENDPOINT
                    value: unix:///csi/csi.sock
                imagePullPolicy: "Always"
                securityContext:
                  privileged: true
                  capabilities:
                    add: [ "SYS_ADMIN" ]
                  allowPrivilegeEscalation: true
                volumeMounts:
                  - name: plugin-dir
                    mountPath: /csi
                  - name: pods-mount-dir
                    mountPath: /var/lib/k0s/kubelet
                    mountPropagation: "Bidirectional"
                  - mountPath: /dev
                    name: device-dir
            volumes:
              - name: registration-dir
                hostPath:
                  path: /var/lib/k0s/kubelet/plugins_registry/
                  type: DirectoryOrCreate
              - name: kubelet-dir
                hostPath:
                  path: /var/lib/k0s/kubelet
                  type: Directory
              - name: plugin-dir
                hostPath:
                  path: /var/lib/k0s/kubelet/plugins/block.csi.vultr.com
                  type: DirectoryOrCreate
              - name: pods-mount-dir
                hostPath:
                  path: /var/lib/k0s/kubelet
                  type: Directory
              - name: device-dir
                hostPath:
                  path: /dev
              - name: udev-rules-etc
                hostPath:
                  path: /etc/udev
                  type: Directory
              - name: udev-rules-lib
                hostPath:
                  path: /lib/udev
                  type: Directory
              - name: udev-socket
                hostPath:
                  path: /run/udev
                  type: Directory
              - name: sys
                hostPath:
                  path: /sys
                  type: Directory

      ---
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: csi-vultr-node-sa
        namespace: kube-system

      ---
      kind: ClusterRoleBinding
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: driver-registrar-binding
        namespace: kube-system
      subjects:
        - kind: ServiceAccount
          name: csi-vultr-node-sa
          namespace: kube-system
      roleRef:
        kind: ClusterRole
        name: csi-vultr-node-driver-registrar-role
        apiGroup: rbac.authorization.k8s.io

      ---
      kind: ClusterRole
      apiVersion: rbac.authorization.k8s.io/v1
      metadata:
        name: csi-vultr-node-driver-registrar-role
        namespace: kube-system
      rules:
        - apiGroups: [ "" ]
          resources: [ "events" ]
          verbs: [ "get", "list", "watch", "create", "update", "patch" ]
    EOT
    destination = "/var/lib/k0s/manifests/vultr/vultr-csi-${var.vultr_csi_version}.yaml"
  }
}

locals {
  kubeconfig_filename = "admin-${terraform.workspace}.conf"
}

resource "null_resource" "create_kubeconfig" {
  depends_on = [
    null_resource.k0s
  ]

  triggers = {
    cluster = null_resource.k0s.id
  }

  count = var.write_kubeconfig ? 1 : 0

  provisioner "local-exec" {
    command = "sleep 10; rm ${local.kubeconfig_filename}; k0sctl kubeconfig > ${local.kubeconfig_filename}"
  }
}

locals {
  kubeconfig = "${abspath(path.root)}/${local.kubeconfig_filename}"
}
