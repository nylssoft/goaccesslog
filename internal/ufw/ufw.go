package ufw

// Provides an interface to the universal firewall used to add or remove REJECT firewall rules
// for IP addresses.
//
// Each added firewall rule has an expiration date.
// The rule will expire after 1 hour if the IP address is added for the first time.
// The expiration date will increase by a factor 1 << (reject count) to a maximum of 1024 hours.
//
// Requires sudo permissions.
//
// Use NewUfw to create a new firewall object.
type Ufw interface {
	// Initializes the firewall object.
	// Reads all rejected IP addresses for REJECT firewall rules marked with the used comment.
	Init()
	// Returns whether the specified IP addresses is rejected by a firewall rule.
	IsRejected(ip string) bool
	// Rejects the specified IP address.
	// Adds a REJECT firewall rule with the used comment for the specified IP address.
	Reject(ip string) bool
	// Releases all rejected IP addresses.
	// All REJECT firewall rules that are marked with the used comment are deleted.
	ReleaseAll()
	// Releases firewall rules that are expired.
	// All REJECT firewall rules that are expired and marked with the used comment are deleted.
	ReleaseIfExpired()
	// Releases the firewall rule for the specified IP address.
	// The REJECT firewall rule with the used comment and the specified IP address as source is deleted.
	Release(ip string)
}

// Creates a new firewall object with the specified comment for REJECT firewall rules.
func NewUfw(comment string) Ufw {
	var ufw ufw_impl
	ufw.comment = comment
	ufw.ips = make(map[string]info)
	return &ufw
}
