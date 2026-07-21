package dnstapcollector

import (
	"testing"
	"time"
)

func TestPairEventsUsesEchoedQueryTimeAndHandlesOutOfOrderFrames(t *testing.T) {
	firstTime := time.Date(2026, time.July, 19, 10, 0, 0, 0, time.UTC)
	secondTime := firstTime.Add(time.Second)
	firstQuery := pairingEvent(2, EventResolverQuery, firstTime)
	secondQuery := pairingEvent(4, EventResolverQuery, secondTime)
	firstResponse := pairingEvent(3, EventResolverResponse, firstTime)
	secondResponse := pairingEvent(1, EventResolverResponse, secondTime)

	exchanges, summary := pairEvents([]Event{secondResponse, firstQuery, firstResponse, secondQuery})
	if summary.Integrity != PairingExact || summary.Matched != 2 || len(exchanges) != 2 {
		t.Fatalf("pairing = %+v exchanges %+v", summary, exchanges)
	}
	for _, exchange := range exchanges {
		if exchange.Status != PairMatched {
			t.Fatalf("exchange = %+v", exchange)
		}
	}
	if exchanges[0].QuerySequence != 2 || exchanges[0].ResponseSequence != 3 ||
		exchanges[1].QuerySequence != 4 || exchanges[1].ResponseSequence != 1 {
		t.Fatalf("exchanges = %+v", exchanges)
	}
}

func TestPairEventsRefusesAmbiguousCollision(t *testing.T) {
	queryTime := time.Now().UTC()
	events := []Event{
		pairingEvent(1, EventResolverQuery, queryTime),
		pairingEvent(2, EventResolverQuery, queryTime),
		pairingEvent(3, EventResolverResponse, queryTime),
	}
	exchanges, summary := pairEvents(events)
	if summary.Integrity != PairingHasAmbiguity || summary.Ambiguous != 1 || summary.NoResponse != 2 || summary.Matched != 0 {
		t.Fatalf("pairing = %+v", summary)
	}
	if len(exchanges) != 3 {
		t.Fatalf("exchanges = %+v", exchanges)
	}
	foundAmbiguous := false
	for _, exchange := range exchanges {
		if exchange.Status == PairAmbiguous && len(exchange.CandidateQuerySequences) == 2 {
			foundAmbiguous = true
		}
	}
	if !foundAmbiguous {
		t.Fatalf("ambiguous evidence = %+v", exchanges)
	}
}

func TestPairEventsPreservesOrphanResponseAndNoResponse(t *testing.T) {
	queryTime := time.Now().UTC()
	query := pairingEvent(1, EventResolverQuery, queryTime)
	response := pairingEvent(2, EventResolverResponse, queryTime.Add(time.Second))
	exchanges, summary := pairEvents([]Event{query, response})
	if summary.Integrity != PairingHasOrphans || summary.OrphanResponses != 1 || summary.NoResponse != 1 {
		t.Fatalf("pairing = %+v", summary)
	}
	if len(exchanges) != 2 {
		t.Fatalf("exchanges = %+v", exchanges)
	}
}

func pairingEvent(sequence uint64, kind EventKind, queryTime time.Time) Event {
	return Event{
		Sequence: sequence, Kind: kind, Family: FamilyIPv4, Protocol: ProtocolUDP,
		LocalPort: 53000, UpstreamIP: "192.0.2.53", UpstreamPort: 53,
		QueryTime: queryTime, ResponseTime: queryTime.Add(10 * time.Millisecond),
		DNSID: 0x4242, Question: Question{Name: "example.com.", Type: 1, Class: 1},
		QueryWire: []byte{1, 2, 3},
	}
}
