package dnstapcollector

import (
	"bytes"
	"sort"
	"time"
)

type pairKey struct {
	family       SocketFamily
	protocol     SocketProtocol
	localPort    uint16
	upstreamIP   string
	upstreamPort uint16
	dnsID        uint16
	name         string
	qtype        uint16
	qclass       uint16
}

func pairEvents(events []Event) ([]Exchange, PairingSummary) {
	queries := make(map[pairKey][]int)
	matched := make([]bool, len(events))
	for index := range events {
		if events[index].Kind == EventResolverQuery {
			key := pairingKey(events[index])
			queries[key] = append(queries[key], index)
		}
	}

	exchanges := make([]Exchange, 0, len(events))
	summary := PairingSummary{Integrity: PairingExact}
	for responseIndex := range events {
		response := events[responseIndex]
		if response.Kind != EventResolverResponse {
			continue
		}
		candidates := exactCandidates(events, queries[pairingKey(response)], matched, response)
		switch len(candidates) {
		case 0:
			exchanges = append(exchanges, Exchange{
				Status: PairOrphanResponse, ResponseSequence: response.Sequence,
				StartedAt: response.QueryTime, FinishedAt: response.ResponseTime,
			})
			summary.OrphanResponses++
			if summary.Integrity == PairingExact {
				summary.Integrity = PairingHasOrphans
			}
		case 1:
			queryIndex := candidates[0]
			query := events[queryIndex]
			matched[queryIndex] = true
			exchanges = append(exchanges, Exchange{
				Status: PairMatched, QuerySequence: query.Sequence, ResponseSequence: response.Sequence,
				StartedAt: query.QueryTime, FinishedAt: response.ResponseTime,
				Duration: response.ResponseTime.Sub(query.QueryTime),
			})
			summary.Matched++
		default:
			sequences := make([]uint64, 0, len(candidates))
			for _, candidate := range candidates {
				sequences = append(sequences, events[candidate].Sequence)
			}
			exchanges = append(exchanges, Exchange{
				Status: PairAmbiguous, ResponseSequence: response.Sequence,
				CandidateQuerySequences: sequences,
				StartedAt:               response.QueryTime, FinishedAt: response.ResponseTime,
			})
			summary.Ambiguous++
			summary.Integrity = PairingHasAmbiguity
		}
	}

	for index := range events {
		if events[index].Kind != EventResolverQuery || matched[index] {
			continue
		}
		exchanges = append(exchanges, Exchange{
			Status: PairNoResponse, QuerySequence: events[index].Sequence,
			StartedAt: events[index].QueryTime,
		})
		summary.NoResponse++
	}

	sort.SliceStable(exchanges, func(left, right int) bool {
		leftTime := exchangeSortTime(exchanges[left])
		rightTime := exchangeSortTime(exchanges[right])
		if !leftTime.Equal(rightTime) {
			return leftTime.Before(rightTime)
		}
		leftSequence := exchanges[left].QuerySequence
		if leftSequence == 0 {
			leftSequence = exchanges[left].ResponseSequence
		}
		rightSequence := exchanges[right].QuerySequence
		if rightSequence == 0 {
			rightSequence = exchanges[right].ResponseSequence
		}
		return leftSequence < rightSequence
	})
	return exchanges, summary
}

func pairingKey(event Event) pairKey {
	return pairKey{
		family: event.Family, protocol: event.Protocol, localPort: event.LocalPort,
		upstreamIP: event.UpstreamIP, upstreamPort: event.UpstreamPort,
		dnsID: event.DNSID, name: event.Question.Name,
		qtype: event.Question.Type, qclass: event.Question.Class,
	}
}

func exactCandidates(events []Event, candidates []int, matched []bool, response Event) []int {
	result := make([]int, 0, len(candidates))
	for _, index := range candidates {
		query := events[index]
		if matched[index] || !query.QueryTime.Equal(response.QueryTime) {
			continue
		}
		if len(response.QueryWire) != 0 && !bytes.Equal(query.QueryWire, response.QueryWire) {
			continue
		}
		result = append(result, index)
	}
	return result
}

func exchangeSortTime(exchange Exchange) time.Time {
	if !exchange.StartedAt.IsZero() {
		return exchange.StartedAt
	}
	return exchange.FinishedAt
}
