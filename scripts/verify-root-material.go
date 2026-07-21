package main

import (
	"fmt"
	"os"
	"reflect"
	"time"

	"nodeping/internal/dnsroots"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verify-root-material <named.root> <root-anchors.xml>")
		os.Exit(2)
	}
	hints, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	hintsSummary, err := dnsroots.ParseRootHints(hints)
	if err != nil {
		fatal(err)
	}
	anchors, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatal(err)
	}
	anchorSummary, err := dnsroots.ParseIANAAnchorXML(anchors, time.Now().UTC())
	if err != nil {
		fatal(err)
	}
	if !reflect.DeepEqual(anchorSummary.ActiveKeyTags, []uint16{20326, 38696}) {
		fatal(fmt.Errorf("active IANA root KSK tags = %v, want [20326 38696]", anchorSummary.ActiveKeyTags))
	}
	fmt.Printf("root_material_verified root_servers=%d ipv4=%d ipv6=%d active_ksk_tags=%v\n",
		hintsSummary.RootServerCount, hintsSummary.IPv4Count, hintsSummary.IPv6Count, anchorSummary.ActiveKeyTags)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
