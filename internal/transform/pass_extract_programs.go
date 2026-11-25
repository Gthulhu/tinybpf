package transform

import (
	"fmt"
	"io"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

// extractProgramsModule keeps only the specified BPF program functions and removes runtime functions.
func extractProgramsModule(m *ir.Module, programNames []string, verbose bool, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	programSet, err := buildProgramSet(m, programNames)
	if err != nil {
		return err
	}
	if verbose {
		for name := range programSet {
			fmt.Fprintf(w, "[transform] keeping program: %s\n", name)
		}
	}
	if len(programNames) == 0 && len(programSet) > 1 {
		names := make([]string, 0, len(programSet))
		for name := range programSet {
			names = append(names, name)
		}
		fmt.Fprintf(w, "[transform] auto-detected %d programs: %v (use --programs to select explicitly)\n",
			len(names), names)
	}
	if len(programNames) > 0 {
		includeProgramDependencies(m, programSet)
	}
	for _, fn := range m.Functions {
		if !programSet[fn.Name] {
			fn.Removed = true
		}
	}
	for i := range m.Entries {
		entry := &m.Entries[i]
		if entry.Kind == ir.TopFunction && entry.Function != nil && entry.Function.Removed {
			entry.Removed = true
		}
	}
	markRuntimeGlobalsRemoved(m)
	return nil
}

// includeProgramDependencies retains functions referenced by selected programs
// and by user globals, which are kept as data sections even if unreferenced.
func includeProgramDependencies(m *ir.Module, keep map[string]bool) {
	definitions := make(map[string]ir.TopLevelEntry)
	for _, entry := range m.Entries {
		if entry.Function != nil {
			definitions[entry.Function.Name] = entry
		} else if entry.Global != nil && !isRuntimeGlobal(entry.Global.Name) {
			definitions[entry.Global.Name] = entry
		}
	}
	queue := make([]string, 0, len(keep))
	for name := range keep {
		queue = append(queue, name)
	}
	for name, entry := range definitions {
		if entry.Global != nil {
			queue = append(queue, name)
		}
	}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		entry, ok := definitions[name]
		if !ok {
			continue
		}
		for _, line := range entryTextLines(entry) {
			for i := 0; i < len(line); i++ {
				if line[i] != '@' {
					continue
				}
				start := i + 1
				end := start
				for end < len(line) && (isIdentCharByte(line[end]) || line[end] == '-' || line[end] == '$') {
					end++
				}
				ref := line[start:end]
				dep, exists := definitions[ref]
				if exists && !seen[ref] && (dep.Function == nil || !isRuntimeFunc(ref)) {
					if dep.Function != nil {
						keep[ref] = true
					}
					queue = append(queue, ref)
				}
				i = end - 1
			}
		}
	}
}

// buildProgramSet resolves which functions to keep based on explicit names or auto-detection.
func buildProgramSet(m *ir.Module, programNames []string) (map[string]bool, error) {
	programSet := make(map[string]bool)
	if len(programNames) > 0 {
		defined := make(map[string]bool, len(m.Functions))
		for _, fn := range m.Functions {
			defined[fn.Name] = true
		}
		var missing []string
		for _, n := range programNames {
			if !defined[n] {
				missing = append(missing, n)
			}
			programSet[n] = true
		}
		if len(missing) > 0 {
			available := make([]string, len(m.Functions))
			for i, fn := range m.Functions {
				available[i] = fn.Name
			}
			return nil, fmt.Errorf("requested program(s) not found in IR: %v (available: %v)", missing, available)
		}
	} else {
		for _, fn := range m.Functions {
			if !isRuntimeFunc(fn.Name) {
				programSet[fn.Name] = true
			}
		}
	}
	if len(programSet) == 0 {
		names := make([]string, len(m.Functions))
		for i, fn := range m.Functions {
			names[i] = fn.Name
		}
		return nil, fmt.Errorf("no program functions found among: %v", names)
	}
	return programSet, nil
}

// markRuntimeGlobalsRemoved flags runtime-internal globals for removal.
func markRuntimeGlobalsRemoved(m *ir.Module) {
	for _, g := range m.Globals {
		if strings.HasPrefix(g.Name, "runtime.") || g.Name == ".string" ||
			strings.HasPrefix(g.Name, "__bpf_core_") {
			g.Modified = true
			markGlobalRemoved(m, g)
		}
	}
}

// markGlobalRemoved flags the module entry associated with the given global as removed.
func markGlobalRemoved(m *ir.Module, g *ir.Global) {
	for i := range m.Entries {
		if m.Entries[i].Global == g {
			m.Entries[i].Removed = true
			break
		}
	}
}
