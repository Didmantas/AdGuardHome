package client

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/arpdb"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/log"
)

// DHCP is an interface for accessing DHCP lease data the [Storage] needs.
type DHCP interface {
	// Leases returns all the DHCP leases.
	Leases() (leases []*dhcpsvc.Lease)

	// HostByIP returns the hostname of the DHCP client with the given IP
	// address.  The address will be netip.Addr{} if there is no such client,
	// due to an assumption that a DHCP client must always have a hostname.
	HostByIP(ip netip.Addr) (host string)

	// MACByIP returns the MAC address for the given IP address leased.  It
	// returns nil if there is no such client, due to an assumption that a DHCP
	// client must always have a MAC address.
	MACByIP(ip netip.Addr) (mac net.HardwareAddr)
}

type emptyDHCP struct{}

// type check
var _ DHCP = emptyDHCP{}

func (emptyDHCP) Leases() (_ []*dhcpsvc.Lease) { return nil }

func (emptyDHCP) HostByIP(_ netip.Addr) (_ string) { return "" }

func (emptyDHCP) MACByIP(_ netip.Addr) (_ net.HardwareAddr) { return nil }

// Config is the client storage configuration structure.
type Config struct {
	DHCP     DHCP
	EtcHosts *aghnet.HostsContainer
	ARPDB    arpdb.Interface

	// AllowedTags is a list of all allowed client tags.
	AllowedTags []string

	InitialClients         []*Persistent
	ARPClientsUpdatePeriod time.Duration
}

// Storage contains information about persistent and runtime clients.
type Storage struct {
	// allowedTags is a set of all allowed tags.
	allowedTags *container.MapSet[string]

	// mu protects indexes of persistent and runtime clients.
	mu *sync.Mutex

	// index contains information about persistent clients.
	index *index

	// runtimeIndex contains information about runtime clients.
	runtimeIndex *RuntimeIndex

	dhcp                   DHCP
	etcHosts               *aghnet.HostsContainer
	arpDB                  arpdb.Interface
	arpClientsUpdatePeriod time.Duration
}

// NewStorage returns initialized client storage.  conf must not be nil.
func NewStorage(conf *Config) (s *Storage, err error) {
	allowedTags := container.NewMapSet(conf.AllowedTags...)
	s = &Storage{
		allowedTags:            allowedTags,
		mu:                     &sync.Mutex{},
		index:                  newIndex(),
		runtimeIndex:           NewRuntimeIndex(),
		dhcp:                   cmp.Or(conf.DHCP, DHCP(emptyDHCP{})),
		etcHosts:               conf.EtcHosts,
		arpDB:                  conf.ARPDB,
		arpClientsUpdatePeriod: conf.ARPClientsUpdatePeriod,
	}

	for i, p := range conf.InitialClients {
		err = s.Add(p)
		if err != nil {
			return nil, fmt.Errorf("adding client %q at index %d: %w", p.Name, i, err)
		}
	}

	return s, nil
}

// Start starts the goroutines for updating the runtime client information.
func (s *Storage) Start() {
	go s.periodicARPUpdate()
	go s.handleHostsUpdates()
}

// periodicARPUpdate periodically reloads runtime clients from ARP.  It is
// intended to be used as a goroutine.
func (s *Storage) periodicARPUpdate() {
	defer log.OnPanic("storage")

	for {
		s.ReloadARP()
		time.Sleep(s.arpClientsUpdatePeriod)
	}
}

// ReloadARP reloads runtime clients from ARP, if configured.
func (s *Storage) ReloadARP() {
	if s.arpDB != nil {
		s.addFromSystemARP()
	}
}

// addFromSystemARP adds the IP-hostname pairings from the output of the arp -a
// command.
func (s *Storage) addFromSystemARP() {
	if err := s.arpDB.Refresh(); err != nil {
		s.arpDB = arpdb.Empty{}
		log.Error("refreshing arp container: %s", err)

		return
	}

	ns := s.arpDB.Neighbors()
	if len(ns) == 0 {
		log.Debug("refreshing arp container: the update is empty")

		return
	}

	var rcs []*Runtime
	for _, n := range ns {
		rc := NewRuntime(n.IP)
		rc.SetInfo(SourceARP, []string{n.Name})

		rcs = append(rcs, rc)
	}

	added, removed := s.BatchUpdateBySource(SourceARP, rcs)
	log.Debug("storage: added %d, removed %d client aliases from arp neighborhood", added, removed)
}

// handleHostsUpdates receives the updates from the hosts container and adds
// them to the clients storage.  It is intended to be used as a goroutine.
func (s *Storage) handleHostsUpdates() {
	defer log.OnPanic("storage")

	for upd := range s.etcHosts.Upd() {
		s.addFromHostsFile(upd)
	}
}

// addFromHostsFile fills the client-hostname pairing index from the system's
// hosts files.
func (s *Storage) addFromHostsFile(hosts *hostsfile.DefaultStorage) {
	var rcs []*Runtime
	hosts.RangeNames(func(addr netip.Addr, names []string) (cont bool) {
		// Only the first name of the first record is considered a canonical
		// hostname for the IP address.
		//
		// TODO(e.burkov):  Consider using all the names from all the records.
		rc := NewRuntime(addr)
		rc.SetInfo(SourceHostsFile, []string{names[0]})

		rcs = append(rcs, rc)

		return true
	})

	added, removed := s.BatchUpdateBySource(SourceHostsFile, rcs)
	log.Debug("storage: added %d, removed %d client aliases from system hosts file", added, removed)
}

// type check
var _ AddressUpdater = (*Storage)(nil)

// UpdateAddress implements the [AddressUpdater] interface for *Storage
func (s *Storage) UpdateAddress(ip netip.Addr, host string, info *whois.Info) {
	// Common fast path optimization.
	if host == "" && info == nil {
		return
	}

	if host != "" {
		rc := NewRuntime(ip)
		rc.SetInfo(SourceRDNS, []string{host})
		s.UpdateRuntime(rc)
	}

	if info != nil {
		s.setWHOISInfo(ip, info)
	}
}

// setWHOISInfo sets the WHOIS information for a runtime client.
func (s *Storage) setWHOISInfo(ip netip.Addr, wi *whois.Info) {
	_, ok := s.Find(ip.String())
	if ok {
		log.Debug("storage: client for %s is already created, ignore whois info", ip)

		return
	}

	rc := NewRuntime(ip)
	rc.SetWHOIS(wi)
	s.UpdateRuntime(rc)

	log.Debug("storage: set whois info for runtime client with ip %s: %+v", ip, wi)
}

// Add stores persistent client information or returns an error.
func (s *Storage) Add(p *Persistent) (err error) {
	defer func() { err = errors.Annotate(err, "adding client: %w") }()

	err = p.validate(s.allowedTags)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	err = s.index.clashesUID(p)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	err = s.index.clashes(p)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.index.add(p)

	log.Debug("client storage: added %q: IDs: %q [%d]", p.Name, p.IDs(), s.index.size())

	return nil
}

// FindByName finds persistent client by name.  And returns its shallow copy.
func (s *Storage) FindByName(name string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.findByName(name)
	if ok {
		return p.ShallowClone(), ok
	}

	return nil, false
}

// Find finds persistent client by string representation of the client ID, IP
// address, or MAC.  And returns its shallow copy.
func (s *Storage) Find(id string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.find(id)
	if ok {
		return p.ShallowClone(), ok
	}

	ip, err := netip.ParseAddr(id)
	if err != nil {
		return nil, false
	}

	foundMAC := s.dhcp.MACByIP(ip)
	if foundMAC != nil {
		return s.FindByMAC(foundMAC)
	}

	return nil, false
}

// FindLoose is like [Storage.Find] but it also tries to find a persistent
// client by IP address without zone.  It strips the IPv6 zone index from the
// stored IP addresses before comparing, because querylog entries don't have it.
// See TODO on [querylog.logEntry.IP].
//
// Note that multiple clients can have the same IP address with different zones.
// Therefore, the result of this method is indeterminate.
func (s *Storage) FindLoose(ip netip.Addr, id string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.find(id)
	if ok {
		return p.ShallowClone(), ok
	}

	p = s.index.findByIPWithoutZone(ip)
	if p != nil {
		return p.ShallowClone(), true
	}

	return nil, false
}

// FindByMAC finds persistent client by MAC and returns its shallow copy.  s.mu
// is expected to be locked.
func (s *Storage) FindByMAC(mac net.HardwareAddr) (p *Persistent, ok bool) {
	p, ok = s.index.findByMAC(mac)
	if ok {
		return p.ShallowClone(), ok
	}

	return nil, false
}

// RemoveByName removes persistent client information.  ok is false if no such
// client exists by that name.
func (s *Storage) RemoveByName(name string) (ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.index.findByName(name)
	if !ok {
		return false
	}

	if err := p.CloseUpstreams(); err != nil {
		log.Error("client storage: removing client %q: %s", p.Name, err)
	}

	s.index.remove(p)

	return true
}

// Update finds the stored persistent client by its name and updates its
// information from p.
func (s *Storage) Update(name string, p *Persistent) (err error) {
	defer func() { err = errors.Annotate(err, "updating client: %w") }()

	err = p.validate(s.allowedTags)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.index.findByName(name)
	if !ok {
		return fmt.Errorf("client %q is not found", name)
	}

	// Client p has a newly generated UID, so replace it with the stored one.
	//
	// TODO(s.chzhen):  Remove when frontend starts handling UIDs.
	p.UID = stored.UID

	err = s.index.clashes(p)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.index.remove(stored)
	s.index.add(p)

	return nil
}

// RangeByName calls f for each persistent client sorted by name, unless cont is
// false.
func (s *Storage) RangeByName(f func(c *Persistent) (cont bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.index.rangeByName(f)
}

// Size returns the number of persistent clients.
func (s *Storage) Size() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.index.size()
}

// CloseUpstreams closes upstream configurations of persistent clients.
func (s *Storage) CloseUpstreams() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.index.closeUpstreams()
}

// ClientRuntime returns a copy of the saved runtime client by ip.  If no such
// client exists, returns nil.
func (s *Storage) ClientRuntime(ip netip.Addr) (rc *Runtime) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rc = s.runtimeIndex.Client(ip)
	if rc != nil {
		return rc
	}

	host := s.dhcp.HostByIP(ip)
	if host == "" {
		return nil
	}

	rc = NewRuntime(ip)
	rc.SetInfo(SourceDHCP, []string{host})
	s.UpdateRuntime(rc)

	return rc
}

// UpdateRuntime updates the stored runtime client with information from rc.  If
// no such client exists, saves the copy of rc in storage.  rc must not be nil.
func (s *Storage) UpdateRuntime(rc *Runtime) (added bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.updateRuntimeLocked(rc)
}

// updateRuntimeLocked updates the stored runtime client with information from
// rc.  rc must not be nil.  Storage.mu is expected to be locked.
func (s *Storage) updateRuntimeLocked(rc *Runtime) (added bool) {
	stored := s.runtimeIndex.Client(rc.ip)
	if stored == nil {
		s.runtimeIndex.Add(rc.Clone())

		return true
	}

	if rc.whois != nil {
		stored.whois = rc.whois.Clone()
	}

	if rc.arp != nil {
		stored.arp = slices.Clone(rc.arp)
	}

	if rc.rdns != nil {
		stored.rdns = slices.Clone(rc.rdns)
	}

	if rc.dhcp != nil {
		stored.dhcp = slices.Clone(rc.dhcp)
	}

	if rc.hostsFile != nil {
		stored.hostsFile = slices.Clone(rc.hostsFile)
	}

	return false
}

// BatchUpdateBySource updates the stored runtime clients information from the
// specified source and returns the number of added and removed clients.
func (s *Storage) BatchUpdateBySource(src Source, rcs []*Runtime) (added, removed int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rc := range s.runtimeIndex.index {
		rc.unset(src)
	}

	for _, rc := range rcs {
		if s.updateRuntimeLocked(rc) {
			added++
		}
	}

	for ip, rc := range s.runtimeIndex.index {
		if rc.isEmpty() {
			delete(s.runtimeIndex.index, ip)
			removed++
		}
	}

	return added, removed
}

// SizeRuntime returns the number of the runtime clients.
func (s *Storage) SizeRuntime() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.runtimeIndex.Size()
}

// RangeRuntime calls f for each runtime client in an undefined order.
func (s *Storage) RangeRuntime(f func(rc *Runtime) (cont bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.runtimeIndex.Range(f)
}

// DeleteBySource removes all runtime clients that have information only from
// the specified source and returns the number of removed clients.
//
// TODO(s.chzhen):  Use it.
func (s *Storage) DeleteBySource(src Source) (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.runtimeIndex.DeleteBySource(src)
}
