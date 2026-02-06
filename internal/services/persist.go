package services

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type PersistService struct {
	configDir string
}

func NewPersistService(configDir string) *PersistService {
	return &PersistService{configDir: configDir}
}

func (s *PersistService) ExportConfig() ([]byte, error) {
	// Create a temporary file for the archive
	tmpFile, err := os.CreateTemp("", "router-config-*.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(tmpFile)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Walk through config directory and add files
	err = filepath.Walk(s.configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(s.configDir, path)
		if err != nil {
			return err
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// If it's a file, write the content
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create archive: %w", err)
	}

	// Close writers to flush data
	tarWriter.Close()
	gzWriter.Close()

	// Read the file content
	tmpFile.Seek(0, 0)
	return io.ReadAll(tmpFile)
}

func (s *PersistService) ImportConfig(reader io.Reader) error {
	// Create gzip reader
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Construct full path
		targetPath := filepath.Join(s.configDir, header.Name)

		// Ensure the path is within config directory (security check)
		if !filepath.HasPrefix(targetPath, s.configDir) {
			return fmt.Errorf("invalid path in archive: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			// Create file
			file, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			file.Close()

			// Set file permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set permissions: %w", err)
			}
		}
	}

	return nil
}

func (s *PersistService) RestoreAll(
	iptables *IPTablesService,
	routes *IPRouteService,
	rules *IPRuleService,
) error {
	var errors []string

	if err := iptables.RestoreRules(); err != nil {
		errors = append(errors, "iptables: "+err.Error())
	}

	if err := routes.RestoreRoutes(); err != nil {
		errors = append(errors, "routes: "+err.Error())
	}

	if err := rules.RestoreRules(); err != nil {
		errors = append(errors, "rules: "+err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("some configurations failed to restore: %v", errors)
	}

	return nil
}

// GenerateSystemdService generates a systemd service file content
func (s *PersistService) GenerateSystemdService(binaryPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Linux Router GUI
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5
User=root
WorkingDirectory=%s

# Security settings
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
`, binaryPath, filepath.Dir(binaryPath))
}

// GenerateRestoreScript generates a script to restore network configuration on boot
func (s *PersistService) GenerateRestoreScript() string {
	return fmt.Sprintf(`#!/bin/bash
# Linux Router Configuration Restore Script
# This script restores saved network configuration on boot

CONFIG_DIR="%s"

# Restore iptables rules
if [ -f "$CONFIG_DIR/iptables/rules.v4" ]; then
    echo "Restoring iptables rules..."
    iptables-restore < "$CONFIG_DIR/iptables/rules.v4"
fi

# Restore routes
for table_file in "$CONFIG_DIR/routes"/*.conf; do
    if [ -f "$table_file" ]; then
        table=$(basename "$table_file" .conf)
        echo "Restoring routes for table: $table"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            [[ "$line" =~ ^# ]] && continue
            if [ "$table" = "main" ]; then
                ip route add $line 2>/dev/null || true
            else
                ip route add $line table "$table" 2>/dev/null || true
            fi
        done < "$table_file"
    fi
done

# Restore IP rules
if [ -f "$CONFIG_DIR/rules/ip-rules.conf" ]; then
    echo "Restoring IP rules..."
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [[ "$line" =~ ^# ]] && continue
        ip rule add $line 2>/dev/null || true
    done < "$CONFIG_DIR/rules/ip-rules.conf"
fi

echo "Network configuration restored."
`, s.configDir)
}
