package ds

import (
	"sync"
)

func GetSyncMapSize(m *sync.Map) int {
	size := 0
	m.Range(func(_, _ interface{}) bool {
		size++
		return true
	})

	return size
}

