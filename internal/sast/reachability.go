package sast

import "container/list"

// ReachabilityConfig configures a traversal over a graph snapshot.
type ReachabilityConfig struct {
	Snapshot   Snapshot
	Edge       EdgeKind
	Entrypoint []SymbolID
}

// ReachabilityResult captures the boolean outcome plus the witness path when a
// symbol is reachable from any entrypoint.
type ReachabilityResult struct {
	Reachable bool
	Path      []SymbolID
}

// Reachability performs a breadth-first search over the provided snapshot.
func Reachability(cfg ReachabilityConfig, target SymbolID) ReachabilityResult {
	if len(cfg.Entrypoint) == 0 {
		return ReachabilityResult{}
	}

	targetKey := target.String()
	visited := make(map[string]SymbolID)
	parent := make(map[string]string)
	queue := list.New()

	for _, entry := range cfg.Entrypoint {
		key := entry.String()
		queue.PushBack(entry)
		visited[key] = entry
	}

	for queue.Len() > 0 {
		e := queue.Front()
		queue.Remove(e)
		current := e.Value.(SymbolID)
		curKey := current.String()
		if curKey == targetKey {
			return ReachabilityResult{
				Reachable: true,
				Path:      reconstructPath(visited, parent, targetKey),
			}
		}
		succ := cfg.Snapshot.Successors(cfg.Edge, current)
		for _, id := range succ {
			key := id.String()
			if _, ok := visited[key]; ok {
				continue
			}
			visited[key] = id
			parent[key] = curKey
			queue.PushBack(id)
		}
	}

	return ReachabilityResult{}
}

func reconstructPath(visited map[string]SymbolID, parent map[string]string, targetKey string) []SymbolID {
	var reversed []SymbolID
	for key := targetKey; key != ""; {
		sym, ok := visited[key]
		if !ok {
			break
		}
		reversed = append(reversed, sym)
		next, ok := parent[key]
		if !ok {
			break
		}
		key = next
	}
	for i := 0; i < len(reversed)/2; i++ {
		j := len(reversed) - 1 - i
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed
}
