//go:build !unix

package config

// openNonBlock is none where there are no FIFOs to wait on: lwconf in a browser
const openNonBlock = 0
