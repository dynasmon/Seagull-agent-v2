package protocol

// What the agent writes on the wire, each changing on its own: Version on every
// batch, EventSchemaVersion on every event and InventorySchemaVersion on every
// inventory record. None of them is the release of the agent.
const (
	Version                = 1
	EventSchemaVersion     = 1
	InventorySchemaVersion = 1
)
