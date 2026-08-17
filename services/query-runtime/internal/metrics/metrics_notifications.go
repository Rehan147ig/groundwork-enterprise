package metrics

// Notification delivery metrics (Milestone 5). Failed security
// notifications are an alerting surface: an emergency access event must
// never succeed without an acknowledged delivery, so every failure is
// counted per tenant/channel and every rejected interactive action is
// counted by reason.

// RecordNotificationFailure counts one failed security notification
// delivery after the retry budget. channel is "slack" or "teams".
func RecordNotificationFailure(tenantID, channel string) {
	NotificationFailuresTotal.WithLabelValues(tenantID, channel).Inc()
}

// RecordNotificationSignatureRejected counts one interactive action
// request rejected on signature or replay verification. reason is one
// of "invalid_signature", "replay_window".
func RecordNotificationSignatureRejected(reason string) {
	NotificationSignaturesRejectedTotal.WithLabelValues(reason).Inc()
}
