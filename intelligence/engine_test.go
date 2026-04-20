package intelligence

import (
	"testing"
	"time"
)

func TestEngine_ThreatScoring(t *testing.T) {
	e := NewEngine(ModeAdaptive)
	
	// Simulate clean network
	snap := MetricsSnapshot{
		RTT:        50 * time.Millisecond,
		RTTStdDev:  2 * time.Millisecond,
		PacketLoss: 0,
		Throughput: 1024 * 1024,
	}
	
	score := e.calculateThreatScore(snap, nil, nil)
	if score > 10 {
		t.Errorf("expected low score for clean network, got %d", score)
	}
	
	// Simulate throttling
	snapThrottled := MetricsSnapshot{
		RTT:        50 * time.Millisecond,
		RTTStdDev:  5 * time.Millisecond,
		PacketLoss: 0.15,
		Throughput: 50 * 1024,
	}
	
	scoreT := e.calculateThreatScore(snapThrottled, nil, nil)
	if scoreT < 40 {
		t.Errorf("expected high score for throttled network, got %d", scoreT)
	}
}

func TestEngine_StateTransitions(t *testing.T) {
	e := NewEngine(ModeAdaptive)
	
	// High score should trigger Blocked state
	state := e.nextState(80, MetricsSnapshot{}, nil)
	if state != StateBlocked {
		t.Errorf("expected StateBlocked, got %s", state)
	}
	
	// Test Hysteresis
	e.activeState = StateBlocked
	e.lastScores = []int{80, 80, 80}
	
	// Score drops slightly but average is still high
	state2 := e.nextState(50, MetricsSnapshot{}, nil)
	if state2 != StateBlocked {
		t.Errorf("expected state to stay Blocked due to hysteresis, got %s", state2)
	}
	
	// Score drops significantly
	e.lastScores = []int{10, 10, 10}
	state3 := e.nextState(10, MetricsSnapshot{}, nil)
	if state3 != StateOptimal {
		t.Errorf("expected state to return to Optimal, got %s", state3)
	}
}
