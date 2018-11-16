package ds

import (
	"time"
	"github.com/symphonyprotocol/log"
)

var dsLogger = log.GetLogger("Data-structure")

type ParallelTask struct {
	IsFinished	bool
	Result	interface{}
	Body	func([]interface{}, func(interface{})) 
	Params	[]interface{}
}

func (p *ParallelTask) Run() {
	p.Body(p.Params, func(res interface{}) { 
		dsLogger.Trace("Task finished with result: %v", res)
		p.Result = res 
		p.IsFinished = true
	})
}

type SequentialParallelTaskQueue struct {
	TaskChannel	chan *ParallelTask
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
	}
}

func (p *SequentialParallelTaskQueue) AddTask(t *ParallelTask) {
	p.TaskChannel <- t
}

func (p *SequentialParallelTaskQueue) Execute() {
	go func() {
		for {
			time.Sleep(time.Millisecond)
			p.CheckFinishedTasksInSequential()
			count := p.GetRunningTasksCount()
			if count >= p.ParallelSize {
				continue
			}
			select {
			case task := <- p.TaskChannel:
				dsLogger.Trace("Going to run the task: %v", task)
				p.TasksInProgress = append(p.TasksInProgress, task)
				task.Run()
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
