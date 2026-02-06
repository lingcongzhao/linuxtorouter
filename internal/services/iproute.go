package services

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"linuxtorouter/internal/models"
)

type IPRouteService struct {
	configDir string
}

func NewIPRouteService(configDir string) *IPRouteService {
	return &IPRouteService{configDir: configDir}
}

func (s *IPRouteService) ListRoutes(table string) ([]models.Route, error) {
	args := []string{"route", "show"}
	if table != "" && table != "main" {
		args = append(args, "table", table)
	}

	cmd := exec.Command("ip", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	return s.parseRouteOutput(string(output), table)
}

func (s *IPRouteService) ListAllRoutes() ([]models.Route, error) {
	cmd := exec.Command("ip", "route", "show", "table", "all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list all routes: %w", err)
	}

	return s.parseRouteOutput(string(output), "")
}

func (s *IPRouteService) parseRouteOutput(output, defaultTable string) ([]models.Route, error) {
	var routes []models.Route
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		route := s.parseRouteLine(line, defaultTable)
		if route != nil {
			routes = append(routes, *route)
		}
	}

	return routes, nil
}

func (s *IPRouteService) parseRouteLine(line, defaultTable string) *models.Route {
	route := &models.Route{
		Table: defaultTable,
	}

	parts := strings.Fields(line)
	if len(parts) < 1 {
		return nil
	}

	// First element is usually destination or "default"
	route.Destination = parts[0]

	// Parse key-value pairs
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "via":
			if i+1 < len(parts) {
				route.Gateway = parts[i+1]
				i++
			}
		case "dev":
			if i+1 < len(parts) {
				route.Interface = parts[i+1]
				i++
			}
		case "proto":
			if i+1 < len(parts) {
				route.Protocol = parts[i+1]
				i++
			}
		case "scope":
			if i+1 < len(parts) {
				route.Scope = parts[i+1]
				i++
			}
		case "src":
			if i+1 < len(parts) {
				route.Source = parts[i+1]
				i++
			}
		case "metric":
			if i+1 < len(parts) {
				route.Metric, _ = strconv.Atoi(parts[i+1])
				i++
			}
		case "table":
			if i+1 < len(parts) {
				route.Table = parts[i+1]
				i++
			}
		}
	}

	// Handle route type
	if strings.HasPrefix(route.Destination, "broadcast") ||
		strings.HasPrefix(route.Destination, "local") ||
		strings.HasPrefix(route.Destination, "unreachable") {
		typeParts := strings.SplitN(route.Destination, " ", 2)
		route.Type = typeParts[0]
		if len(typeParts) > 1 {
			route.Destination = typeParts[1]
		}
	}

	return route
}

func (s *IPRouteService) AddRoute(input models.RouteInput) error {
	args := []string{"route", "add"}

	if input.Destination == "" {
		return fmt.Errorf("destination is required")
	}
	args = append(args, input.Destination)

	if input.Gateway != "" {
		args = append(args, "via", input.Gateway)
	}

	if input.Interface != "" {
		args = append(args, "dev", input.Interface)
	}

	if input.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(input.Metric))
	}

	if input.Table != "" && input.Table != "main" {
		args = append(args, "table", input.Table)
	}

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add route: %s", string(output))
	}

	return nil
}

func (s *IPRouteService) DeleteRoute(destination, gateway, iface, table string) error {
	args := []string{"route", "del", destination}

	if gateway != "" {
		args = append(args, "via", gateway)
	}

	if iface != "" {
		args = append(args, "dev", iface)
	}

	if table != "" && table != "main" {
		args = append(args, "table", table)
	}

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete route: %s", string(output))
	}

	return nil
}

func (s *IPRouteService) GetRoutingTables() ([]models.RoutingTable, error) {
	// Read /etc/iproute2/rt_tables
	file, err := os.Open("/etc/iproute2/rt_tables")
	if err != nil {
		// Return default tables if file doesn't exist
		return []models.RoutingTable{
			{ID: 255, Name: "local"},
			{ID: 254, Name: "main"},
			{ID: 253, Name: "default"},
		}, nil
	}
	defer file.Close()

	var tables []models.RoutingTable
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`^\s*(\d+)\s+(\S+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if matches != nil {
			id, _ := strconv.Atoi(matches[1])
			tables = append(tables, models.RoutingTable{
				ID:   id,
				Name: matches[2],
			})
		}
	}

	return tables, nil
}

func (s *IPRouteService) FlushTable(table string) error {
	args := []string{"route", "flush"}
	if table != "" {
		args = append(args, "table", table)
	}

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush routes: %s", string(output))
	}

	return nil
}

func (s *IPRouteService) SaveRoutes() error {
	// Get all routes
	routes, err := s.ListAllRoutes()
	if err != nil {
		return err
	}

	// Group by table
	tableRoutes := make(map[string][]string)
	for _, route := range routes {
		// Skip local and broadcast routes
		if route.Protocol == "kernel" && (route.Scope == "link" || route.Scope == "host") {
			continue
		}
		if route.Type == "local" || route.Type == "broadcast" {
			continue
		}

		table := route.Table
		if table == "" {
			table = "main"
		}

		// Build route command
		cmd := route.Destination
		if route.Gateway != "" {
			cmd += " via " + route.Gateway
		}
		if route.Interface != "" {
			cmd += " dev " + route.Interface
		}
		if route.Metric > 0 {
			cmd += " metric " + strconv.Itoa(route.Metric)
		}

		tableRoutes[table] = append(tableRoutes[table], cmd)
	}

	// Save to files
	for table, cmds := range tableRoutes {
		savePath := filepath.Join(s.configDir, "routes", table+".conf")
		content := strings.Join(cmds, "\n")
		if err := os.WriteFile(savePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to save routes for table %s: %w", table, err)
		}
	}

	return nil
}

func (s *IPRouteService) RestoreRoutes() error {
	routesDir := filepath.Join(s.configDir, "routes")
	files, err := os.ReadDir(routesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".conf") {
			continue
		}

		table := strings.TrimSuffix(file.Name(), ".conf")
		data, err := os.ReadFile(filepath.Join(routesDir, file.Name()))
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			args := []string{"route", "add"}
			args = append(args, strings.Fields(line)...)
			if table != "main" {
				args = append(args, "table", table)
			}

			exec.Command("ip", args...).Run()
		}
	}

	return nil
}
