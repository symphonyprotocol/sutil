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

func ClearSyncMap(m *sync.Map) {
	m.Range(func(key interface{}, value interface{}) bool {
		m.Delete(key)
		return true
	})
}

