package Utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ConfigManager(findData string) (string, error) {
	file, err := os.Open("../sso-auth-service/main.config")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == findData {
			return strings.TrimSpace(parts[1]), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("key %s not found", findData)
}
