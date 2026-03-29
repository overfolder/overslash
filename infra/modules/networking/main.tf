variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

# VPC for private connectivity
resource "google_compute_network" "vpc" {
  name                    = "overslash-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "overslash-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = "10.0.0.0/24"
}

# Private IP range for Cloud SQL
resource "google_compute_global_address" "private_ip" {
  name          = "overslash-private-ip"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

# Private service connection for Cloud SQL
resource "google_service_networking_connection" "private_vpc" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip.name]
}

# Serverless VPC Access connector for Cloud Run → Cloud SQL
resource "google_vpc_access_connector" "connector" {
  name          = "overslash-vpc-connector"
  project       = var.project_id
  region        = var.region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc.name

  min_instances = 2
  max_instances = 3
}

output "vpc_id" {
  value = google_compute_network.vpc.id
}

output "vpc_name" {
  value = google_compute_network.vpc.name
}

output "subnet_id" {
  value = google_compute_subnetwork.subnet.id
}

output "vpc_connector_id" {
  value = google_vpc_access_connector.connector.id
}

output "private_vpc_connection" {
  value = google_service_networking_connection.private_vpc
}
