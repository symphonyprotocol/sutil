package ds

import (
	"time"
	"github.com/symphonyprotocol/log"
)

var dsLogger = log.GetLogger("Data-structure").SetLevel(log.INFO)

type ParallelTask struct {
	IsFinished	bool
	Result	interface{}
	Body	func([]interface{}, func(interface{})) 
	Params	[]interface{}
	taskFinishedQueue	chan struct{}
}

func (p *ParallelTask) Run() {
	p.Body(p.Params, func(res interface{}) { 
		dsLogger.Trace("Task finished with result: %v", res)
		p.Result = res 
		p.IsFinished = true
		p.taskFinishedQueue <- struct{}{}
	})
}

type SequentialParallelTaskQueue struct {
	TaskChannel	chan *ParallelTask
	TaskFinishedQueue	chan struct{}
	ParallelSize	uint
	TasksInProgress	[]*ParallelTask
	ParallelTasksFinishedCallback	func([]*ParallelTask)
}

func NewSequentialParallelTaskQueue(size uint, taskFinishedCallback func([]*ParallelTask)) *SequentialParallelTaskQueue {
	return &SequentialParallelTaskQueue{
		TaskChannel: make(chan *ParallelTask, 100),
		ParallelSize: size,
		TasksInProgress: make([]*ParallelTask, 0, 0),
		ParallelTasksFinishedCallback: taskFinishedCallback,
		TaskFinishedQueue: make(chan struct{}),
	}
}

func (p *SequentialParallelTaskQueue) AddTask(t *ParallelTask) {
	t.taskFinishedQueue = p.TaskFinishedQueue
	p.TaskChannel <- t
}

func (p *SequentialParallelTaskQueue) Execute() {
	go func() {
		for {
			time.Sleep(time.Millisecond)
			count := p.GetRunningTasksCount()
			if count >= p.ParallelSize {
				continue
			}
			select {
			case task := <- p.TaskChannel:
				dsLogger.Trace("Going to run the task: %v", task)
				p.TasksInProgress = append(p.TasksInProgress, task)
				task.Run()
			case <- p.TaskFinishedQueue:
				dsLogger.Trace("Going to check if we need to return tasks")
				p.CheckFinishedTasksInSequential()
			default:
				continue
			}
		}
	}()
}

func (p *SequentialParallelTaskQueue) CheckFinishedTasksInSequential() {
	stopIndex := 0
	for _, t := range p.TasksInProgress {
		dsLogger.Trace("tasksInProgress len: %v, finished : %v", len(p.TasksInProgress), t.IsFinished)
		if t.IsFinished {
			stopIndex++
			dsLogger.Trace("stopIndex++ : %v", stopIndex)
		} else {
			// dsLogger.Trace("stopIndex boom ! ???? : %v", stopIndex)
			break
		}
	}

	if stopIndex > 0 && p.ParallelTasksFinishedCallback != nil {
		dsLogger.Trace("Going to callback, finished stop index: %v", stopIndex)
		p.ParallelTasksFinishedCallback(p.TasksInProgress[0:stopIndex])
		// modify the array
		p.TasksInProgress = p.TasksInProgress[stopIndex:]
	}
}

func (p *SequentialParallelTaskQueue) GetRunningTasksCount() uint {
	var count uint = 0
	for _, t := range p.TasksInProgress {
		if t != nil && !t.IsFinished {
			count++
		}
	}

	return count
}
