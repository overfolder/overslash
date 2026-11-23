# Rotation metadata for CASA 6.7.1. Which secret sits in which class, why, and
# how each class is rotated: docs/compliance/casa/secrets-access-policy.md.
#
# Secret Manager rotates nothing itself. At `next_rotation_time` it publishes a
# SECRET_ROTATE event to the secret's topic and moves the time on by
# `rotation_period`. That is a reminder on a fixed calendar, so it knows nothing
# about when a secret was last really rotated. The control that does is the
# metrics exporter's age sweep (crates/overslash-metrics-exporter), which
# compares each secret's newest enabled version with the period declared here.
#
# Every secret carries a `rotation-class` label, so a secret with neither the
# label nor a period is visible to the sweep as unmeasured. `exempt` means there
# is nothing to rotate. `expire_time` and `ttl` are deliberately not used: they
# delete the secret when they elapse, which would take the API down instead of
# telling someone.

locals {
  rotation_period_days = {
    root-key     = 365
    database     = 180
    internal-key = 180
    third-party  = 365
    sa-key       = 90
  }

  # `next_rotation_time` is only the first reminder: Secret Manager advances it
  # from then on, which is why every secret ignores changes to it. Reading the
  # topic through the IAM member orders each secret after the grant, because
  # the API refuses a topic its service agent cannot publish to.
  rotation = {
    for class, days in local.rotation_period_days : class => {
      period             = "${days * 86400}s"
      next_rotation_time = timeadd(plantimestamp(), "${days * 24}h")
      topic              = google_pubsub_topic_iam_member.secret_manager_publisher.topic
      labels             = { rotation-class = class }
    }
  }

  rotation_exempt_labels = { rotation-class = "exempt" }
}

# The Secret Manager service agent does not exist until something asks for it.
resource "google_project_service_identity" "secret_manager" {
  provider = google-beta
  project  = var.project_id
  service  = "secretmanager.googleapis.com"
}

resource "google_pubsub_topic" "secret_rotation" {
  project = var.project_id
  name    = "${var.base_prefix}-secret-rotation"

  depends_on = [var.pubsub_api]
}

resource "google_pubsub_topic_iam_member" "secret_manager_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.secret_rotation.id
  role    = "roles/pubsub.publisher"
  member  = google_project_service_identity.secret_manager.member
}

# A topic with no subscription drops every message. The topic also carries each
# version add and metadata update, so this keeps only the reminders. An operator
# pulls them to see which secrets came due (`[P2] Secret Rotation Due` fires
# while one is waiting). The events carry names, never payloads.
resource "google_pubsub_subscription" "secret_rotation_due" {
  project = var.project_id
  name    = "${var.base_prefix}-secret-rotation-due"
  topic   = google_pubsub_topic.secret_rotation.id
  filter  = "attributes.eventType = \"SECRET_ROTATE\""

  message_retention_duration = "604800s"

  # The default deletes a subscription after 31 days without a pull, and a
  # reminder can be months apart.
  expiration_policy {
    ttl = ""
  }
}

output "rotation" {
  description = "Rotation settings per class, for modules that create their own secrets: { class => { period, next_rotation_time, topic, labels } }."
  value       = local.rotation
}

output "rotation_subscription_id" {
  value = google_pubsub_subscription.secret_rotation_due.name
}
