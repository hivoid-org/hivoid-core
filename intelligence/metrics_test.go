package intelligence

import (
	"testing"
	"time"
)

func TestMetrics_RecordRTT(t *testing.T) {
	m := NewMetrics()
	
	// Record some values
	m.RecordRTT(100 * time.Millisecond)
	m.RecordRTT(110 * time.Millisecond)
	m.RecordRTT(90 * time.Millisecond)
	
	snap := m.Snapshot()
	
	if snap.RTT == 0 {
		t.Error("expected non-zero RTT")
	}
	
	// Check StdDev (should be ~8.16ms for 90, 100, 110)
	if snap.RTTStdDev == 0 {
		t.Error("expected non-zero StdDev")
	}
	
	t.Logf("RTT: %v, StdDev: %v", snap.RTT, snap.RTTStdDev)
}

func TestMetrics_AtomicLoss(t *testing.T) {
	m := NewMetrics()
	
	m.RecordPacketSent()
	m.RecordPacketSent()
	m.RecordPacketLost()
	
	snap := m.Snapshot()
	if snap.PacketLoss != 0.5 {
		t.Errorf("expected 0.5 loss, got %f", snap.PacketLoss)
	}
}

func TestMetrics_WindowReset(t *testing.T) {
	m := NewMetrics()
	m.windowStart = time.Now().Add(-6 * time.Second)
	
	m.RecordPacketSent()
	m.RecordPacketLost()
	
	snap := m.Snapshot()
	if snap.PacketLoss != 1.0 {
		t.Errorf("expected 1.0 loss, got %f", snap.PacketLoss)
	}
	
	// Next snapshot should be reset
	snap2 := m.Snapshot()
	if snap2.PacketLoss != 0 {
		t.Errorf("expected reset loss, got %f", snap2.PacketLoss)
	}
}
