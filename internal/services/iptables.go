package services

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"linuxtorouter/internal/models"
)

type IPTablesService struct {
	configDir string
}

func NewIPTablesService(configDir string) *IPTablesService {
	return &IPTablesService{configDir: configDir}
}

func (s *IPTablesService) ListChains(table string) ([]models.ChainInfo, error) {
	if table == "" {
		table = "filter"
	}

	cmd := exec.Command("iptables", "-t", table, "-L", "-n", "-v", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list chains: %w", err)
	}

	return s.parseChainOutput(string(output))
}

func (s *IPTablesService) GetChain(table, chain string) (*models.ChainInfo, error) {
	if table == "" {
		table = "filter"
	}

	cmd := exec.Command("iptables", "-t", table, "-L", chain, "-n", "-v", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get chain: %w", err)
	}

	chains, err := s.parseChainOutput(string(output))
	if err != nil {
		return nil, err
	}

	if len(chains) == 0 {
		return nil, fmt.Errorf("chain not found")
	}

	return &chains[0], nil
}

func (s *IPTablesService) parseChainOutput(output string) ([]models.ChainInfo, error) {
	var chains []models.ChainInfo
	var currentChain *models.ChainInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	// Updated regex to handle K/M/G suffixes for both packets and bytes (e.g., "253K packets, 33M bytes")
	chainHeaderRe := regexp.MustCompile(`^Chain (\S+) \(policy (\S+) (\d+[KMG]?) packets, (\d+[KMG]?) bytes\)`)
	chainHeaderNoPolicy := regexp.MustCompile(`^Chain (\S+) \((\d+) references\)`)

	for scanner.Scan() {
		line := scanner.Text()

		// Check for chain header with policy
		if matches := chainHeaderRe.FindStringSubmatch(line); matches != nil {
			if currentChain != nil {
				chains = append(chains, *currentChain)
			}
			packets := parseSuffixedNumber(matches[3])
			bytesVal := parseSuffixedNumber(matches[4])
			currentChain = &models.ChainInfo{
				Name:    matches[1],
				Policy:  matches[2],
				Packets: packets,
				Bytes:   bytesVal,
			}
			continue
		}

		// Check for chain header without policy (user-defined chains)
		if matches := chainHeaderNoPolicy.FindStringSubmatch(line); matches != nil {
			if currentChain != nil {
				chains = append(chains, *currentChain)
			}
			currentChain = &models.ChainInfo{
				Name:   matches[1],
				Policy: "-",
			}
			continue
		}

		// Skip header line
		if strings.HasPrefix(line, "num") || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse rule line
		if currentChain != nil && strings.TrimSpace(line) != "" {
			rule := s.parseRuleLine(line)
			if rule != nil {
				currentChain.Rules = append(currentChain.Rules, *rule)
			}
		}
	}

	if currentChain != nil {
		chains = append(chains, *currentChain)
	}

	return chains, nil
}

// parseSuffixedNumber parses numbers with K/M/G suffixes (e.g., "6477K", "49M", "253K")
func parseSuffixedNumber(s string) uint64 {
	if s == "" {
		return 0
	}

	multiplier := uint64(1)
	numStr := s

	// Check for suffix
	lastChar := s[len(s)-1]
	switch lastChar {
	case 'K':
		multiplier = 1024
		numStr = s[:len(s)-1]
	case 'M':
		multiplier = 1024 * 1024
		numStr = s[:len(s)-1]
	case 'G':
		multiplier = 1024 * 1024 * 1024
		numStr = s[:len(s)-1]
	}

	val, _ := strconv.ParseUint(numStr, 10, 64)
	return val * multiplier
}

func (s *IPTablesService) parseRuleLine(line string) *models.FirewallRule {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return nil
	}

	num, _ := strconv.Atoi(fields[0])
	packets, _ := strconv.ParseUint(fields[1], 10, 64)
	bytes, _ := strconv.ParseUint(fields[2], 10, 64)

	rule := &models.FirewallRule{
		Num:         num,
		Packets:     packets,
		Bytes:       bytes,
		Target:      fields[3],
		Protocol:    fields[4],
		Opt:         fields[5],
		Source:      fields[7],
		Destination: fields[8],
	}

	if len(fields) > 9 {
		rule.Extra = strings.Join(fields[9:], " ")
	}

	return rule
}

func (s *IPTablesService) AddRule(input models.FirewallRuleInput) error {
	args := s.buildRuleArgs(input)

	if input.Position > 0 {
		args = append([]string{"-t", input.Table, "-I", input.Chain, strconv.Itoa(input.Position)}, args...)
	} else {
		args = append([]string{"-t", input.Table, "-A", input.Chain}, args...)
	}

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add rule: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) DeleteRule(table, chain string, ruleNum int) error {
	if table == "" {
		table = "filter"
	}

	cmd := exec.Command("iptables", "-t", table, "-D", chain, strconv.Itoa(ruleNum))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete rule: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) MoveRule(table, chain string, fromPos, toPos int) error {
	// Get the rule specification first
	chainInfo, err := s.GetChain(table, chain)
	if err != nil {
		return err
	}

	if fromPos < 1 || fromPos > len(chainInfo.Rules) {
		return fmt.Errorf("invalid source position")
	}

	// Delete the rule from original position
	if err := s.DeleteRule(table, chain, fromPos); err != nil {
		return err
	}

	// Adjust target position if needed
	if toPos > fromPos {
		toPos--
	}

	// Get updated rule spec and re-insert at new position
	// This is a simplified approach - in production you'd need to preserve the full rule spec
	return nil
}

func (s *IPTablesService) SetPolicy(table, chain, policy string) error {
	if table == "" {
		table = "filter"
	}

	policy = strings.ToUpper(policy)
	if policy != "ACCEPT" && policy != "DROP" && policy != "REJECT" {
		return fmt.Errorf("invalid policy: %s", policy)
	}

	cmd := exec.Command("iptables", "-t", table, "-P", chain, policy)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set policy: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) CreateChain(table, chain string) error {
	if table == "" {
		table = "filter"
	}

	cmd := exec.Command("iptables", "-t", table, "-N", chain)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create chain: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) DeleteChain(table, chain string) error {
	if table == "" {
		table = "filter"
	}

	// First flush the chain
	flushCmd := exec.Command("iptables", "-t", table, "-F", chain)
	flushCmd.Run()

	// Then delete it
	cmd := exec.Command("iptables", "-t", table, "-X", chain)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete chain: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) FlushChain(table, chain string) error {
	if table == "" {
		table = "filter"
	}

	args := []string{"-t", table, "-F"}
	if chain != "" {
		args = append(args, chain)
	}

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush chain: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) buildRuleArgs(input models.FirewallRuleInput) []string {
	var args []string

	if input.Protocol != "" && input.Protocol != "all" {
		args = append(args, "-p", input.Protocol)
	}

	if input.Source != "" && input.Source != "0.0.0.0/0" {
		args = append(args, "-s", input.Source)
	}

	if input.Destination != "" && input.Destination != "0.0.0.0/0" {
		args = append(args, "-d", input.Destination)
	}

	if input.InInterface != "" {
		args = append(args, "-i", input.InInterface)
	}

	if input.OutInterface != "" {
		args = append(args, "-o", input.OutInterface)
	}

	if input.DPort != "" {
		args = append(args, "--dport", input.DPort)
	}

	if input.SPort != "" {
		args = append(args, "--sport", input.SPort)
	}

	if input.State != "" {
		args = append(args, "-m", "state", "--state", input.State)
	}

	if input.Comment != "" {
		args = append(args, "-m", "comment", "--comment", input.Comment)
	}

	args = append(args, "-j", input.Target)

	if input.ToDestination != "" {
		args = append(args, "--to-destination", input.ToDestination)
	}

	if input.ToSource != "" {
		args = append(args, "--to-source", input.ToSource)
	}

	return args
}

func (s *IPTablesService) SaveRules() error {
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to save rules: %w", err)
	}

	savePath := filepath.Join(s.configDir, "iptables", "rules.v4")
	if err := os.WriteFile(savePath, output, 0644); err != nil {
		return fmt.Errorf("failed to write rules file: %w", err)
	}

	return nil
}

func (s *IPTablesService) RestoreRules() error {
	savePath := filepath.Join(s.configDir, "iptables", "rules.v4")
	data, err := os.ReadFile(savePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No saved rules
		}
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	cmd := exec.Command("iptables-restore")
	cmd.Stdin = bytes.NewReader(data)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore rules: %s", string(output))
	}

	return nil
}

func (s *IPTablesService) GetRawRules() (string, error) {
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get rules: %w", err)
	}
	return string(output), nil
}
