package ds

import (
	"time"
)

type ParallelTask struct {
	IsFinished	bool
	Result	interface{}
	Body	func([]interface{}, func(interface{})) 
	Params	[]interface{}
}

func (p *ParallelTask) Run() {
	p.Body(p.Params, func(res interface{}) { 
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
			p.CheckFinishedTasksInSequential()
			count := p.GetRunningTasksCount()
			if count >= p.ParallelSize {
				time.Sleep(time.Millisecond * 5)
				continue
			}
			select {
			case task := <- p.TaskChannel:
				p.TasksInProgress = append(p.TasksInProgress, task)
				task.Run()
			}
		}
	}()
}

func (p *SequentialParallelTaskQueue) CheckFinishedTasksInSequential() {
	stopIndex := 0
	for n, t := range p.TasksInProgress {
		if !t.IsFinished {
			stopIndex = n
			break
		}
	}

	if stopIndex > 0 && p.ParallelTasksFinishedCallback != nil {
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
