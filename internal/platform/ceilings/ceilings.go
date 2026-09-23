package ceilings

// Ceilings are what the operating system enforces on the process the agent
// runs in, whatever the agent itself means to spend: the memory its cgroup may
// hold, the processors' worth of time it may use, the tasks it may run and the
// descriptors it may open. A field left at zero is one nothing enforces.
type Ceilings struct {
	Memory      int64
	CPUs        float64
	Tasks       int64
	Descriptors int64
}

func (c Ceilings) Unenforced() []string {
	named := []string{}
	if c.Memory == 0 {
		named = append(named, "memory")
	}
	if c.CPUs == 0 {
		named = append(named, "cpu")
	}
	if c.Tasks == 0 {
		named = append(named, "tasks")
	}
	if c.Descriptors == 0 {
		named = append(named, "descriptors")
	}
	return named
}
