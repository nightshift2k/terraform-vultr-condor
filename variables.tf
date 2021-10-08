variable "deployment_vultr_api_key" {
  description = "Vultr API Key for the Terraform deployment"
  type        = string
  sensitive   = true
}

variable "cluster_name" {
  description = "A name for your cluster."
  type        = string
  default     = "default"
}

variable "cluster_append_random_id" {
  description = "Wether to append a random id to the cluster name"
  type        = bool
  default     = true
}

variable "cluster_random_id_length" {
  description = "Length of the random id (it will double due to hex conversion, so 2 = 4, 3 = 6, etc.)"
  type        = number
  default     = 2

  validation {
    condition     = var.cluster_random_id_length > 0 && var.cluster_random_id_length <= 8
    error_message = "The cluster_random_id_length value must be between 1 and 8!"
  }  
}

variable "cluster_create_external_dns_hosts" {
  description = "Wether to create DNS hosts for the cluster"
  type        = bool
  default     = false
}

variable "cluster_external_dns_domain" {
  description = "The DNS domain for the cluster, must be hosted in Vultr"
  type        = string
  default     = ""
}

variable "extra_public_keys" {
  description = "Extra(in addition the provisioner key) SSH Keys to add to the cluster nodes."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Vultr deployment region."
  type        = string
  default     = "ewr"
}

variable "node_subnet" {
  description = "Subnet to use for the Vultr Private Network."
  type        = string
  default     = "10.240.0.0/24"
}

variable "controller_count" {
  description = "Number of Control plane nodes."
  type        = number
  default     = 1
}

variable "ha_lb_algorithm" {
  description = "Control Plane VLB balancing algorithm."
  type        = string
  default     = "roundrobin"
}

variable "ha_lb_health_response_timeout" {
  description = "Control Plane VLB healthcheck response timeout."
  type        = number
  default     = 3
}

variable "ha_lb_health_unhealthy_threshold" {
  description = "Control Plane VLB healthcheck unhealthy node threshold."
  type        = number
  default     = 1
}

variable "ha_lb_health_check_interval" {
  description = "Control Plane VLB healthcheck interval."
  type        = number
  default     = 3
}

variable "ha_lb_health_healthy_threshold" {
  description = "Control Plane VLB healthcheck healthy node threshold."
  type        = number
  default     = 2
}

variable "enable_ipv6" {
  description = "Cluster IPv6 for future use NOT CURRENTLY SUPPORTED."
  type        = bool
  default     = false
}

variable "activation_email" {
  description = "Enable/disable cluster node activation emails."
  type        = bool
  default     = false
}

variable "ddos_protection" {
  description = "Enable/disable cluster node DDOS Protection."
  type        = bool
  default     = false
}

variable "tag" {
  description = "Cluster node tags."
  type        = string
  default     = ""
}

variable "worker_count" {
  description = "Number of cluster workers to deploy."
  type        = string
  default     = 3
}

variable "pod_cidr" {
  description = "Pod CIDR Subnet."
  type        = string
  default     = "10.244.0.0/16"
}

variable "svc_cidr" {
  description = "Cluster Service CIDR subnet."
  type        = string
  default     = "10.96.0.0/12"
}

variable "pod_sec_policy" {
  description = "K0s Pod Security Policy."
  type        = string
  default     = "00-k0s-privileged"
}

variable "konnectivity_version" {
  description = "K0s Configuration Konnectivity Version."
  type        = string
  default     = "v0.0.24"
}

variable "metrics_server_version" {
  description = "K0s Configuration Kube Metrics Version."
  type        = string
  default     = "v0.5.1"
}


variable "kube_proxy_version" {
  description = "K0s Configuration Kube Proxy version."
  type        = string
  default     = "v1.22.2"
}

variable "core_dns_version" {
  description = "K0s Configuration CoreDNS version."
  type        = string
  default     = "1.8.0"
}

variable "calico_cni_version" {
  description = "K0s Configuration Calico CNI version."
  type        = string
  default     = "v3.18.1"
}

variable "calico_node_version" {
  description = "K0s Configuration Calico Node version."
  type        = string
  default     = "v3.18.1"
}

variable "calico_kubecontrollers_version" {
  description = "K0s Configuration Calico Node version."
  type        = string
  default     = "v3.18.1"
}

variable "csi_provisioner_version" {
  type    = string
  default = "v3.0.0"
}

variable "csi_attacher_version" {
  type    = string
  default = "v3.3.0"
}

variable "csi_node_driver_registrar_version" {
  type    = string
  default = "v2.3.0"
}


variable "cluster_os" {
  description = "Cluster node OS."
  type        = string
  default     = "Debian 10 x64 (buster)"
}

variable "worker_plan" {
  description = "Cluster worker node Vultr machine type/plan."
  type        = string
  default     = "vc2-2c-4gb"
}

variable "controller_plan" {
  description = "Cluster controller node Vultr machine type/plan."
  type        = string
  default     = "vc2-2c-4gb"
}

variable "k0s_version" {
  description = "K0s Configuration K0s version."
  type        = string
  default     = "v1.22.2+k0s.1"
}

variable "k0s_disable_components" {
  description = "components that should be disabled in the control plane"
  type        =  list(string)
  default     = []
}

variable "write_kubeconfig" {
  description = "Write Kubeconfig locally."
  type        = bool
  default     = true
}

variable "cluster_vultr_api_key" {
  description = "Vultr API Key for CCM and CSI."
  type        = string
  sensitive   = true
  default     = ""
}

variable "vultr_ccm_version" {
  description = "Vultr Cloud Controller Manager version."
  type        = string
  default     = "v0.3.0"
}

variable "vultr_csi_version" {
  description = "Vultr Cloud Storage Interface version."
  type        = string
  default     = "v0.3.0"
}

variable "enable_vultr_ccm" {
  type        = bool
  default     = true
}

variable "enable_vultr_csi" {
  type        = bool
  default     = true
}

variable "control_plane_firewall_rules" {
  description = "Control Plane VLB Firewall Rules."
  type = list(object({
    port    = number
    ip_type = string
    source  = string
  }))
}

variable "allow_ssh" {
  description = "Vultr Firewall Rule to allow SSH globally to all cluster nodes(control plane + workers)."
  type        = bool
  default     = true
}

variable "helm_repositories" {
  description = "Helm repositories to add to the k0s deployment"
  type    = list(map(any))
  default = []
}

variable "helm_charts" {
  description = "Helm charts to add to the k0s deployment"
  type    = list(map(any))
  default = []
}

variable "vultr_csi_image" {
  description = "Vultr CSI image name"
  type    = string
  default = "vultr/vultr-csi"
}

variable "calico_mode" {
  description = "Calico mode"
  type    = string
  default = "bird"
}