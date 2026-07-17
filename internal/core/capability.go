package core

// Capability represents a plugin feature
type Capability string

const (
	// Network capabilities
	CapNetLimit Capability = "netlimit"
	CapTLS      Capability = "tls"
	CapAuth     Capability = "auth"

	// Session capabilities
	CapSessionAware   Capability = "session_aware"
	CapMultiSession   Capability = "multi_session"
	CapSingleInstance Capability = "single_instance"

	// Stream capabilities
	CapBidirectional Capability = "bidirectional"
	CapCompression   Capability = "compression"
)