package ssh

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Pool struct
type Pool struct {
	config  *PoolConfig
	timeout time.Duration
	runSync *sync.Mutex
}

// NewPoolFromYAML func
func NewPoolFromYAML(config string) (*Pool, error) {
	logrus.Debugf("New pool creating...")
	poolConfig, err := NewPoolConfigFromYAML(config)
	if err != nil {
		return nil, err
	}
	pool := &Pool{
		config:  poolConfig,
		runSync: &sync.Mutex{},
	}
	if err := pool.validate(); err != nil {
		return nil, err
	}
	logrus.Debugf("New pool created")
	return pool, nil
}

func (c *Pool) validate() error {
	duration, err := time.ParseDuration(c.config.getTimeout())
	logrus.Debugf("duration: %v", duration.Seconds())
	if err != nil {
		return fmt.Errorf("Validating pool: parsing timeout %s: %v", err, duration.String())
	}
	c.timeout = duration
	return nil
}

// RunCmd func
func (c *Pool) RunCmd(cmd []string) error {
	logrus.Debugf("Pool running cmd...")
	return c.run(cmd)
}

// Run func
func (c *Pool) Run() error {
	logrus.Debugf("Pool running...")
	logrus.Debugf("Pool run locking...")
	c.runSync.Lock()
	cmds := c.config.getCmds()
	c.runSync.Unlock()
	logrus.Debugf("Pool run unlocked")
	return c.run(cmds)
}

func (c *Pool) run(cmds []string) error {
	if cmds == nil || len(cmds) == 0 {
		return fmt.Errorf("Pool run: cmd should be provided")
	}
	var wg sync.WaitGroup
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, os.Kill)

	wgErrors, errStrings := newErrorByChan()
	ctx, cancel := context.WithCancel(context.Background())
	if c.timeout.Nanoseconds() > 0 {
		logrus.Debugf("Pool run timeout: %s", c.timeout.String())
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
	}
	defer cancel()
	for _, host := range c.config.getHosts() {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			_, err := h.Run(ctx, cmds, dialerRunKindCombined)
			if err != nil {
				message := err.Error()
				if len(message) > 0 {
					logrus.Debugf("%s%s", hostDebugIndent, message)
					wgErrors <- &message
				}
			}
		}(host)
	}

	go func() {
		wg.Wait()
		close(wgErrors)
	}()

	for {
		select {
		case errStr := <-wgErrors:
			if errStr != nil {
				errStrings = append(errStrings, *errStr)
			}
			if len(errStrings) > 0 {
				fmt.Printf("error\n")
				return fmt.Errorf("Pool run failed:\n%s", stringsToLines(errStrings))
			}
			fmt.Printf("done\n")
			logrus.Debugf("Pool runned")
			return nil

		case <-exit:
			logrus.Info("Exit signal detected....trying to close properly...")
			cancel()
			<-wgErrors
			fmt.Printf("cancelled\n")
			return fmt.Errorf("Pool run cancelled by user request: %v", ctx.Err())
		case <-ctx.Done():
			<-wgErrors
			reason := "unknown"
			switch ctx.Err() {
			case context.Canceled:
				reason = "cancelled"
			case context.DeadlineExceeded:
				reason = "timeout"
			}
			fmt.Println(reason)
			logrus.Debugf("Pool run %s: %s", reason, ctx.Err())
			return fmt.Errorf("Pool run %s: %v", reason, ctx.Err())
		}
	}
}

// Close func
func (c *Pool) Close() error {
	logrus.Debugf("Pool closing...")
	errStrings := []string{}
	for _, host := range c.config.getHosts() {
		if err := host.Close(); err != nil {
			errStrings = append(errStrings, err.Error())
		}
	}
	if len(errStrings) > 0 {
		fmt.Printf("error\n")
		return fmt.Errorf("Pool close failed:\n%s", stringsToLines(errStrings))
	}
	logrus.Debugf("Pool closed")
	return nil
}
