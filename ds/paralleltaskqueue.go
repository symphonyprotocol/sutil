package ds

import (
	"time"
	"github.com/symphonyprotocol/log"
	"sync"
)

var dsLogger = log.GetLogger("Data-structure").SetLevel(log.INFO)

type ParallelTask struct {
	IsFinished	bool
	Result	interface{}
	Body	func([]interface{}, func(interface{})) 
	Params	[]interface{}
	Timeout	time.Duration
	taskFinishedQueue	chan struct{}
	startTime	time.Time
	isRunning	bool
}

func (p *ParallelTask) Run() {
	p.startTime = time.Now()
	p.isRunning = true
	p.Body(p.Params, func(res interface{}) { 
		dsLogger.Trace("Task finished with result: %v", res)
		p.Result = res 
		p.IsFinished = true
		p.isRunning = false
		p.taskFinishedQueue <- struct{}{}
	})
}

func (p *ParallelTask) Retry() {
	go p.Run()
}

type SequentialParallelTaskQueue struct {
	TaskChannel	chan *ParallelTask
	TaskFinishedQueue	chan struct{}
	ParallelSize	int
	TasksInProgress	[]*ParallelTask
	ParallelTasksFinishedCallback	func([]*ParallelTask)
	mtx	sync.RWMutex
	TimedoutCallback	func([]*ParallelTask)
}

func NewSequentialParallelTaskQueue(size int, taskFinishedCallback func([]*ParallelTask), timedOutCallback func([]*ParallelTask)) *SequentialParallelTaskQueue {
	return &SequentialParallelTaskQueue{
		TaskChannel: make(chan *ParallelTask, size),
		ParallelSize: size,
		TasksInProgress: make([]*ParallelTask, 0, 0),
		ParallelTasksFinishedCallback: taskFinishedCallback,
		TaskFinishedQueue: make(chan struct{}),
		TimedoutCallback: timedOutCallback,
		mtx: sync.RWMutex{},
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
			p.CheckTimedoutTasks()
			count := p.GetRunningTasksCount()
			if count >= p.ParallelSize {
				continue
			}
			select {
			case task := <- p.TaskChannel:
				dsLogger.Trace("Going to run the task: %v", task)
				p.TasksInProgress = append(p.TasksInProgress, task)
				go task.Run()
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
	// p.mtx.Lock()
	// defer p.mtx.Unlock()
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
		if len(p.TasksInProgress) > 0 {
			p.TasksInProgress = p.TasksInProgress[stopIndex:]
		}
	}
}

func (p *SequentialParallelTaskQueue) CheckTimedoutTasks() {
	// p.mtx.Lock()
	// defer p.mtx.Unlock()
	timedOutTasks := make([]*ParallelTask, 0, 0)
	for _, t := range p.TasksInProgress {
		dsLogger.Debug("Checking time %v with timeout %v, isrunning: %v, isfinished: %v", time.Since(t.startTime).Nanoseconds(), t.Timeout.Nanoseconds(), t.isRunning, t.IsFinished)
		if time.Since(t.startTime) > t.Timeout && t.IsFinished == false && t.isRunning == true {
			timedOutTasks = append(timedOutTasks, t)
		}
	}
	if p.TimedoutCallback != nil && len(timedOutTasks) > 0 {
		p.TimedoutCallback(timedOutTasks)
	}
}

func (p *SequentialParallelTaskQueue) GetRunningTasksCount() int {
	// p.mtx.Lock()
	// defer p.mtx.Unlock()
	var count int = 0
	for _, t := range p.TasksInProgress {
		if t != nil && !t.IsFinished && t.isRunning {
			count++
		}
	}

	return count
}

func (p *SequentialParallelTaskQueue) Clear() {
	//p.mtx.Lock()
	p.TasksInProgress = nil
	//p.mtx.Unlock()
	for len(p.TaskChannel) > 0 {
		<-p.TaskChannel
	}
}
