// Package systemdns discovers the operating system's DNS resolvers without
// treating them as public network endpoints. System-discovered resolvers are
// trusted to use private, loopback, and link-local addresses. IPv6 zones are
// retained as local routing metadata and must be omitted by presentation
// layers when publishing peer information.
package systemdns
