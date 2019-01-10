package ds

import (
	"testing"
	"time"
	"github.com/symphonyprotocol/log"
)

func TestTimedOut(t *testing.T) {
	log.SetGlobalLevel(log.TRACE)
	log.Configure(map[string]([]log.Appender){
		"default": []log.Appender{ log.NewConsoleAppender() },
	})
	dsLogger.SetLevel(log.TRACE)
	successChan := make(chan struct{})
	failedChan := make(chan struct{})
	queue := NewSequentialParallelTaskQueue(10, func(tasks []*ParallelTask) {
		t.Log("tasks done")
		failedChan <- struct{}{}
	}, func(tasks []*ParallelTask) {
		t.Log("tasks timedout")
		successChan <- struct{}{}
	})
	queue.Execute()
	queue.AddTask(&ParallelTask{
		Body: func(params []interface{}, cb func(res interface{})) {
			time.Sleep(10 * time.Millisecond)
			cb(666)
		},
		Timeout: 5 * time.Millisecond,
	})
	select {
	case <- failedChan:
		t.Fail()
	case <-successChan:
	}
}
