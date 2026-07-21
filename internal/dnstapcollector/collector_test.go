package dnstapcollector

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	framestream "github.com/farsightsec/golang-framestream"
)

func TestCollectorCompletesOnlyAfterStopFinish(t *testing.T) {
	queryTime := time.Date(2026, time.July, 19, 10, 0, 0, 123, time.UTC)
	queryFrame, responseFrame := resolverFramePair(t, queryTime)
	result, producerErr := collectFrames(t, DefaultLimits(), []byte(ContentType), true, queryFrame, responseFrame)
	if producerErr != nil {
		t.Fatalf("producer: %v", producerErr)
	}
	if !result.Complete || result.Status != CollectionComplete || result.Error != nil {
		t.Fatalf("result = %+v", result)
	}
	if result.FrameCount != 2 || result.FrameBytes != int64(len(queryFrame)+len(responseFrame)) {
		t.Fatalf("frame accounting = count %d bytes %d", result.FrameCount, result.FrameBytes)
	}
	if len(result.Events) != 2 || len(result.Exchanges) != 1 {
		t.Fatalf("evidence = events %d exchanges %d", len(result.Events), len(result.Exchanges))
	}
	exchange := result.Exchanges[0]
	if exchange.Status != PairMatched || exchange.QuerySequence != 1 || exchange.ResponseSequence != 2 {
		t.Fatalf("exchange = %+v", exchange)
	}
	if result.Pairing.Integrity != PairingExact || result.Pairing.Matched != 1 {
		t.Fatalf("pairing = %+v", result.Pairing)
	}
}

func TestCollectorRejectsUnexpectedEOFAndRetainsEvidence(t *testing.T) {
	client, producer := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	queryFrame, _ := resolverFramePair(t, time.Now().UTC())
	producerResult := make(chan error, 1)
	go func() {
		writer, err := framestream.NewWriter(producer, &framestream.WriterOptions{
			ContentTypes: [][]byte{[]byte(ContentType)}, Bidirectional: true, Timeout: time.Second,
		})
		if err == nil {
			_, err = writer.WriteFrame(queryFrame)
		}
		if err == nil {
			err = writer.Flush()
		}
		_ = producer.Close()
		producerResult <- err
	}()

	result := NewDefault().Collect(ctx, client)
	if err := <-producerResult; err != nil {
		t.Fatalf("producer: %v", err)
	}
	if result.Complete || result.Status != CollectionProtocolError || result.Error == nil || result.Error.Code != ErrorUnexpectedEOF {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Events) != 1 || result.Pairing.NoResponse != 1 {
		t.Fatalf("partial evidence = events %d pairing %+v", len(result.Events), result.Pairing)
	}
}

func TestCollectorRejectsPartialAndOversizedFrames(t *testing.T) {
	tests := []struct {
		name     string
		length   uint32
		payload  []byte
		wantCode ErrorCode
	}{
		{name: "partial", length: 10, payload: []byte{1, 2, 3}, wantCode: ErrorInvalidControlFlow},
		{name: "oversized", length: 1025, payload: make([]byte, 1025), wantCode: ErrorFrameTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.MaxFrameBytes = 1024
			client, producer := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			producerDone := make(chan error, 1)
			go func() {
				_, err := framestream.NewWriter(producer, &framestream.WriterOptions{
					ContentTypes: [][]byte{[]byte(ContentType)}, Bidirectional: true, Timeout: time.Second,
				})
				if err == nil {
					err = binary.Write(producer, binary.BigEndian, test.length)
				}
				if err == nil {
					_, err = producer.Write(test.payload)
				}
				_ = producer.Close()
				producerDone <- err
			}()
			collector, err := New(limits)
			if err != nil {
				t.Fatalf("new collector: %v", err)
			}
			result := collector.Collect(ctx, client)
			if err := <-producerDone; err != nil {
				t.Fatalf("producer: %v", err)
			}
			if result.Complete || result.Error == nil || result.Error.Code != test.wantCode {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestCollectorRejectsContentTypeMismatch(t *testing.T) {
	result, producerErr := collectFrames(t, DefaultLimits(), []byte("protobuf:other.Type"), true)
	if producerErr == nil {
		t.Fatal("producer unexpectedly negotiated a mismatched content type")
	}
	if result.Status != CollectionProtocolError || result.Error == nil || result.Error.Code != ErrorContentType {
		t.Fatalf("result = %+v", result)
	}
}

func TestCollectorRequiresCallerDeadline(t *testing.T) {
	client, producer := net.Pipe()
	result := NewDefault().Collect(context.Background(), client)
	_ = producer.Close()
	if result.Status != CollectionProtocolError || result.Error == nil || result.Error.Code != ErrorHandshakeFailed {
		t.Fatalf("result = %+v", result)
	}
}

func TestCollectorDeadlineRetainsHandshakeState(t *testing.T) {
	client, producer := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	producerReady := make(chan error, 1)
	go func() {
		_, err := framestream.NewWriter(producer, &framestream.WriterOptions{
			ContentTypes: [][]byte{[]byte(ContentType)}, Bidirectional: true, Timeout: time.Second,
		})
		producerReady <- err
	}()
	result := NewDefault().Collect(ctx, client)
	_ = producer.Close()
	if err := <-producerReady; err != nil && !errors.Is(err, net.ErrClosed) {
		var networkError net.Error
		if !errors.As(err, &networkError) {
			t.Fatalf("producer: %v", err)
		}
	}
	if result.Status != CollectionDeadlineExceeded || result.Error == nil || result.Error.Code != ErrorDeadlineExceeded {
		t.Fatalf("result = %+v", result)
	}
}

func TestCollectorEnforcesEventAndOutstandingLimits(t *testing.T) {
	queryTime := time.Now().UTC()
	queryFrame, responseFrame := resolverFramePair(t, queryTime)

	eventLimits := DefaultLimits()
	eventLimits.MaxEvents = 1
	eventLimits.MaxOutstandingQuery = 1
	result, _ := collectFrames(t, eventLimits, []byte(ContentType), true, queryFrame, responseFrame)
	if result.Status != CollectionLimitExceeded || result.Error == nil || result.Error.Code != ErrorEventLimit {
		t.Fatalf("event limit result = %+v", result)
	}
	if len(result.Events) != 1 || result.Pairing.NoResponse != 1 {
		t.Fatalf("event limit partial evidence = events %d pairing %+v", len(result.Events), result.Pairing)
	}

	secondQuery, _ := resolverFramePair(t, queryTime.Add(time.Second))
	outstandingLimits := DefaultLimits()
	outstandingLimits.MaxOutstandingQuery = 1
	result, producerErr := collectFrames(t, outstandingLimits, []byte(ContentType), true, queryFrame, secondQuery)
	if producerErr != nil {
		t.Fatalf("producer: %v", producerErr)
	}
	if result.Status != CollectionLimitExceeded || result.Error == nil || result.Error.Code != ErrorOutstandingLimit {
		t.Fatalf("outstanding result = %+v", result)
	}
	if len(result.Events) != 2 || result.Pairing.NoResponse != 2 {
		t.Fatalf("outstanding evidence = events %d pairing %+v", len(result.Events), result.Pairing)
	}
}

func collectFrames(t *testing.T, limits Limits, contentType []byte, cleanStop bool, frames ...[]byte) (Result, error) {
	t.Helper()
	collector, err := New(limits)
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}
	client, producer := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	producerResult := make(chan error, 1)
	go func() {
		writer, writeErr := framestream.NewWriter(producer, &framestream.WriterOptions{
			ContentTypes: [][]byte{contentType}, Bidirectional: true, Timeout: time.Second,
		})
		for _, frame := range frames {
			if writeErr != nil {
				break
			}
			_, writeErr = writer.WriteFrame(frame)
		}
		if writeErr == nil {
			writeErr = writer.Flush()
		}
		if writeErr == nil && cleanStop {
			writeErr = writer.Close()
		}
		_ = producer.Close()
		producerResult <- writeErr
	}()
	result := collector.Collect(ctx, client)
	return result, <-producerResult
}
