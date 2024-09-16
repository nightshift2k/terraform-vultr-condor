output "cluster_id" {
  value = random_id.cluster.hex
}

output "cluster_name" {
  value = local.cluster_name
}

output "cluster_network_id" {
  value = vultr_private_network.cluster.id
}

output "control_plane_lb_id" {
  value = vultr_load_balancer.control_plane_ha.*.id
}

output "control_plane_address" {
  value = local.ingress_ip
}

/* output "control_plane_ha_fqdn" { */
/*   value = format("%s.%s", vultr_dns_record.control_plane_ha_dns_record[0].name, vultr_dns_record.control_plane_ha_dns_record[0].domain) */
/* } */

output "controller_fqdns" {
  value = [
    for r in vultr_dns_record.control_plane_dns_records :
      join(".", [ r.name, r.domain ])
  ]
}

output "worker_fqdns" {
  value = [
    for r in vultr_dns_record.worker_dns_records :
      join(".", [ r.name, r.domain ])
  ]
}

output "cluster_firewall_group_id" {
  value = vultr_firewall_group.cluster.id
}

output "controller_ips" {
  value = vultr_instance.control_plane.*.main_ip
}

output "controller_ids" {
  value = vultr_instance.control_plane.*.id
}

output "worker_ips" {
  value = vultr_instance.worker.*.main_ip
}

output "worker_ids" {
  value = vultr_instance.worker.*.id
}

output "private_key_root_file" {
  value = local_file.private_key_root.filename
}

output "public_key_root_file" {
  value = local_file.public_key_root.filename
}

output "kubeconfig" {
  value = local.kubeconfig
  depends_on = [ 
    # first k0s must be successfully created
    null_resource.create_kubeconfig
  ]
}

