package ids

import "github.com/google/uuid"

func NextUUID() string {
	return uuid.New().String()
}
