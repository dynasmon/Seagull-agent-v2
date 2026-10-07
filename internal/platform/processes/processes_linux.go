//go:build linux

package processes

import "context"

func List(ctx context.Context, most int) ([]Process, error) { return list(ctx, proc, most) }
