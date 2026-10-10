package policy

import (
	"fmt"
	"math"
	"slices"
	"strconv"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

var (
	named = map[policyv1.Module]string{
		policyv1.Module_MODULE_AUTHENTICATION: "authentication",
		policyv1.Module_MODULE_INVENTORY:      "inventory",
		policyv1.Module_MODULE_PROCESSES:      "processes",
		policyv1.Module_MODULE_FILES:          "files",
		policyv1.Module_MODULE_NETWORK:        "network",
	}
	levels = map[policyv1.LogLevel]string{
		policyv1.LogLevel_LOG_LEVEL_DEBUG: "debug",
		policyv1.LogLevel_LOG_LEVEL_INFO:  "info",
		policyv1.LogLevel_LOG_LEVEL_WARN:  "warn",
		policyv1.LogLevel_LOG_LEVEL_ERROR: "error",
	}
)

type Kept struct {
	Setting string
	Own     string
	Asked   string
}

// The configuration the agent runs on under a policy: its own, with what the
// policy sets laid over it. A budget the policy sets lowers the agent's ceiling
// and never raises it, so where the agent's own is lower it stays, and is
// reported as kept. Nothing else the agent runs on is reachable from a policy,
// and the result is held to every rule the configuration file is held to.
func Overlay(local config.Config, settings *policyv1.Settings) (config.Config, []Kept, error) {
	candidate := local
	candidate.Modules = make(config.Modules, len(local.Modules))
	for name, held := range local.Modules {
		held.Paths, held.Exclude = slices.Clone(held.Paths), slices.Clone(held.Exclude)
		candidate.Modules[name] = held
	}

	if level := settings.GetLogLevel(); level != policyv1.LogLevel_LOG_LEVEL_UNSPECIFIED {
		written, known := levels[level]
		if !known {
			return config.Config{}, nil, fmt.Errorf("%w: settings.log_level is %d, which names no level", ErrMalformed, level)
		}
		candidate.Logging.Level = written
	}
	seen := map[policyv1.Module]bool{}
	for index, module := range settings.GetModules() {
		name, known := named[module.GetModule()]
		switch {
		case module.GetModule() == policyv1.Module_MODULE_UNSPECIFIED:
			return config.Config{}, nil, fmt.Errorf("%w: settings.modules[%d] names no module", ErrMalformed, index)
		case !known:
			return config.Config{}, nil, fmt.Errorf("%w: settings.modules[%d] names module %d, which this build does not have", ErrInapplicable, index, module.GetModule())
		case seen[module.GetModule()]:
			return config.Config{}, nil, fmt.Errorf("%w: settings.modules names %s twice", ErrMalformed, name)
		}
		seen[module.GetModule()] = true
		held := candidate.Modules[name]
		switch module.GetCollection() {
		case policyv1.Collection_COLLECTION_ENABLED:
			held.Enabled = true
		case policyv1.Collection_COLLECTION_DISABLED:
			held.Enabled = false
		case policyv1.Collection_COLLECTION_UNSPECIFIED:
		default:
			return config.Config{}, nil, fmt.Errorf("%w: settings.modules[%d].collection is %d", ErrMalformed, index, module.GetCollection())
		}
		if every := module.GetInterval(); every != nil {
			if every.CheckValid() != nil {
				return config.Config{}, nil, fmt.Errorf("%w: settings.modules[%d].interval is not a duration", ErrMalformed, index)
			}
			if value := every.AsDuration(); value != 0 {
				held.Interval = config.Duration(value)
			}
		}
		if paths := module.GetPaths(); paths != nil {
			held.Paths = append([]string{}, paths.GetPaths()...)
		}
		if exclude := module.GetExclude(); exclude != nil {
			held.Exclude = slices.Clone(exclude.GetPaths())
		}
		candidate.Modules[name] = held
	}

	var kept []Kept
	budgets := settings.GetBudgets()
	sized(&candidate.Spool.MaxBytes, budgets.GetSpoolMaxBytes(), "spool.max_bytes", &kept)
	sized(&candidate.Transport.MaxBatchBytes, budgets.GetMaxBatchBytes(), "transport.max_batch_bytes", &kept)
	sized(&candidate.Transport.MaxUploadBytesPerSecond, budgets.GetMaxUploadBytesPerSecond(), "transport.max_upload_bytes_per_second", &kept)
	sized(&candidate.Resources.MemoryLimit, budgets.GetMemoryLimitBytes(), "resources.memory_limit", &kept)
	sized(&candidate.Resources.MaxScanBytesPerSecond, budgets.GetMaxScanBytesPerSecond(), "resources.max_scan_bytes_per_second", &kept)
	counted(&candidate.Transport.MaxEventsPerBatch, budgets.GetMaxEventsPerBatch(), "transport.max_events_per_batch", &kept)
	counted(&candidate.Transport.MaxInventoryRecordsPerBatch, budgets.GetMaxInventoryRecordsPerBatch(), "transport.max_inventory_records_per_batch", &kept)
	counted(&candidate.Resources.MaxConcurrentScans, budgets.GetMaxConcurrentScans(), "resources.max_concurrent_scans", &kept)
	counted(&candidate.Resources.MaxConcurrentUploads, budgets.GetMaxConcurrentUploads(), "resources.max_concurrent_uploads", &kept)
	if err := timed(&candidate.Spool.MaxAge, budgets.GetSpoolMaxAge(), "spool.max_age", &kept); err != nil {
		return config.Config{}, nil, err
	}

	made, err := config.Validated(candidate)
	if err != nil {
		return config.Config{}, nil, fmt.Errorf("%w: %w", ErrInapplicable, err)
	}
	return made, kept, nil
}

func sized(held *config.Size, asked uint64, setting string, kept *[]Kept) {
	switch {
	case asked == 0:
	case asked < math.MaxInt64 && config.Size(asked) <= *held:
		*held = config.Size(asked)
	default:
		*kept = append(*kept, Kept{Setting: setting, Own: held.String(), Asked: strconv.FormatUint(asked, 10) + "B"})
	}
}

func counted(held *int, asked uint32, setting string, kept *[]Kept) {
	switch {
	case asked == 0:
	case int64(asked) <= int64(*held):
		*held = int(asked)
	default:
		*kept = append(*kept, Kept{Setting: setting, Own: strconv.Itoa(*held), Asked: strconv.FormatUint(uint64(asked), 10)})
	}
}

func timed(held *config.Duration, asked *durationpb.Duration, setting string, kept *[]Kept) error {
	if asked == nil {
		return nil
	}
	if asked.CheckValid() != nil {
		return fmt.Errorf("%w: settings.budgets.%s is not a duration", ErrMalformed, setting)
	}
	switch value := config.Duration(asked.AsDuration()); {
	case value == 0:
	case value <= *held:
		*held = value
	default:
		*kept = append(*kept, Kept{Setting: setting, Own: held.String(), Asked: value.String()})
	}
	return nil
}
