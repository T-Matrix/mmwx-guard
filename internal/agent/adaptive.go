package agent

import (
	"context"
	"fmt"

	"github.com/T-Matrix/mmwx-guard/internal/firewall"
	"github.com/T-Matrix/mmwx-guard/internal/model"
)

const (
	adaptiveTriggerSamples = 2
	adaptiveRecoverSamples = 12
)

type adaptiveController struct {
	manager     *firewall.Manager
	highSamples int
	lowSamples  int
}

func newAdaptiveController(manager *firewall.Manager) *adaptiveController {
	return &adaptiveController{manager: manager}
}

func (a *adaptiveController) Observe(ctx context.Context, telemetry *model.Telemetry) (string, error) {
	policy, err := a.manager.CurrentPolicy()
	if err != nil {
		telemetry.Adaptive = a.manager.AdaptiveStatus()
		return "", nil
	}
	status := a.manager.AdaptiveStatus()
	status.Enabled = policy.Adaptive.Enabled
	if !policy.Adaptive.Enabled {
		a.highSamples, a.lowSamples = 0, 0
		if status.Emergency {
			if err := a.manager.SetAdaptiveEmergency(ctx, policy, false, ""); err != nil {
				telemetry.Adaptive = status
				return "", err
			}
			status = a.manager.AdaptiveStatus()
			status.Enabled = false
			telemetry.Adaptive = status
			return "recovered", nil
		}
		telemetry.Adaptive = status
		return "", nil
	}

	reason, pressured := adaptivePressure(policy.Adaptive, *telemetry)
	if !status.Emergency {
		a.lowSamples = 0
		if pressured {
			a.highSamples++
		} else {
			a.highSamples = 0
		}
		if a.highSamples >= adaptiveTriggerSamples {
			if err := a.manager.SetAdaptiveEmergency(ctx, policy, true, reason); err != nil {
				telemetry.Adaptive = status
				return "", err
			}
			a.highSamples = 0
			status = a.manager.AdaptiveStatus()
			status.Enabled = true
			telemetry.Adaptive = status
			return "activated", nil
		}
		telemetry.Adaptive = status
		return "", nil
	}

	a.highSamples = 0
	if adaptiveRecovered(policy.Adaptive, *telemetry) {
		a.lowSamples++
	} else {
		a.lowSamples = 0
	}
	if a.lowSamples >= adaptiveRecoverSamples {
		if err := a.manager.SetAdaptiveEmergency(ctx, policy, false, ""); err != nil {
			telemetry.Adaptive = status
			return "", err
		}
		a.lowSamples = 0
		status = a.manager.AdaptiveStatus()
		status.Enabled = true
		telemetry.Adaptive = status
		return "recovered", nil
	}
	telemetry.Adaptive = status
	return "", nil
}

func adaptivePressure(rule model.AdaptiveRule, telemetry model.Telemetry) (string, bool) {
	if telemetry.ConntrackMax > 0 {
		percent := conntrackUsagePercent(telemetry.Conntrack, telemetry.ConntrackMax)
		if percent >= float64(rule.TriggerConntrackPercent) {
			return fmt.Sprintf("Conntrack %.0f%%", percent), true
		}
	}
	if telemetry.Sockets.Total >= rule.TriggerConnections {
		return fmt.Sprintf("入站连接 %d", telemetry.Sockets.Total), true
	}
	syn := telemetry.Sockets.SynRecv + telemetry.Sockets.SynSent
	if syn >= rule.TriggerSYN {
		return fmt.Sprintf("SYN 堆积 %d", syn), true
	}
	return "", false
}

func adaptiveRecovered(rule model.AdaptiveRule, telemetry model.Telemetry) bool {
	conntrackRecovered := telemetry.ConntrackMax == 0 || conntrackUsagePercent(telemetry.Conntrack, telemetry.ConntrackMax) <= float64(rule.RecoverConntrackPercent)
	syn := telemetry.Sockets.SynRecv + telemetry.Sockets.SynSent
	return conntrackRecovered && telemetry.Sockets.Total <= rule.RecoverConnections && syn <= rule.RecoverSYN
}

func conntrackUsagePercent(value, maximum uint64) float64 {
	if maximum == 0 {
		return 0
	}
	return float64(value) / float64(maximum) * 100
}
