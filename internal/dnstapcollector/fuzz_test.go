package dnstapcollector

import (
	"testing"
	"time"
)

func FuzzDecodeFrame(f *testing.F) {
	query, response, err := selfCheckFrames(time.Date(2026, time.July, 19, 10, 0, 0, 0, time.UTC))
	if err != nil {
		f.Fatalf("build seeds: %v", err)
	}
	f.Add(query)
	f.Add(response)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > defaultMaxFrameBytes {
			return
		}
		event, err := decodeFrame(frame, 1)
		if err != nil {
			return
		}
		if event.Sequence != 1 || event.FrameBytes != len(frame) {
			t.Fatalf("decoded accounting = %+v for %d bytes", event, len(frame))
		}
		if event.Kind != EventResolverQuery && event.Kind != EventResolverResponse {
			t.Fatalf("decoded kind = %q", event.Kind)
		}
		if event.Question.Name == "" || event.LocalPort == 0 || event.UpstreamPort == 0 || event.UpstreamIP == "" {
			t.Fatalf("decoded required fields = %+v", event)
		}
	})
}

func FuzzPairEvents(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{1, 1, 1, 1, 1, 1, 1, 1})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128 {
			return
		}
		base := time.Date(2026, time.July, 19, 10, 0, 0, 0, time.UTC)
		events := make([]Event, 0, len(input))
		for index, value := range input {
			kind := EventResolverQuery
			if value&1 != 0 {
				kind = EventResolverResponse
			}
			event := pairingEvent(uint64(index+1), kind, base.Add(time.Duration((value>>1)%8)*time.Millisecond))
			event.DNSID = uint16(value >> 4)
			event.LocalPort += uint16((value >> 2) & 3)
			events = append(events, event)
		}
		exchanges, summary := pairEvents(events)
		if len(exchanges) > len(events) {
			t.Fatalf("%d events produced %d exchanges", len(events), len(exchanges))
		}
		counts := PairingSummary{Integrity: summary.Integrity}
		for _, exchange := range exchanges {
			switch exchange.Status {
			case PairMatched:
				counts.Matched++
			case PairNoResponse:
				counts.NoResponse++
			case PairOrphanResponse:
				counts.OrphanResponses++
			case PairAmbiguous:
				counts.Ambiguous++
			default:
				t.Fatalf("unknown exchange status %q", exchange.Status)
			}
		}
		if counts != summary {
			t.Fatalf("summary = %+v, counted %+v", summary, counts)
		}
	})
}
