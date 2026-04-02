package gpg

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// YkmanAvailable returns true if the ykman CLI is installed.
func YkmanAvailable() bool {
	_, err := exec.LookPath("ykman")
	return err == nil
}

type (
	// YkmanDeviceInfo holds info from `ykman info`.
	YkmanDeviceInfo struct {
		DeviceType      string // e.g. "YubiKey 5 NFC"
		Serial          string
		FirmwareVersion string
		FormFactor      string
	}
)

// YkmanInfo runs `ykman info` and parses the output.
func (c *Client) YkmanInfo(ctx context.Context) (*YkmanDeviceInfo, error) {
	out, err := c.execYkman(ctx, "info")
	if err != nil {
		return nil, fmt.Errorf("ykman info: %w", err)
	}
	return parseYkmanInfo(string(out))
}

func (c *Client) execYkman(ctx context.Context, args ...string) ([]byte, error) {
	ykmanPath, err := exec.LookPath("ykman")
	if err != nil {
		return nil, fmt.Errorf("ykman not found: %w", err)
	}

	c.logger.DebugContext(ctx, "ykman exec",
		slog.String("args", strings.Join(args, " ")),
	)

	cmd := exec.CommandContext(ctx, ykmanPath, args...) //nolint:gosec // ykman path from LookPath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ykman %s: %w\nstderr: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return stdout.Bytes(), nil
}

// parseYkmanInfo parses `ykman info` output.
// Example output:
//
//	Device type: YubiKey 5 NFC
//	Serial number: 12345678
//	Firmware version: 5.4.3
//	Form factor: Keychain (USB-A)
func parseYkmanInfo(output string) (*YkmanDeviceInfo, error) {
	info := &YkmanDeviceInfo{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, ":"); ok {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch k {
			case "Device type":
				info.DeviceType = v
			case "Serial number":
				info.Serial = v
			case "Firmware version":
				info.FirmwareVersion = v
			case "Form factor":
				info.FormFactor = v
			}
		}
	}
	if info.DeviceType == "" {
		return nil, fmt.Errorf("ykman info: could not parse device type")
	}
	return info, nil
}
