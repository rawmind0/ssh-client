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

func (c *Pool) SetCmd(config string) error {
	logrus.Debugf("Cmd setting...")
	poolConfig, err := NewPoolConfigFromYAML(config)
	if err != nil {
		return err
	}
	poolConfig = c.config
	err = c.config.validate()
	if err != nil {
		return fmt.Errorf("Setting cmd: %v", err)
	}

	logrus.Debugf("Setting cmd locking...")
	c.runSync.Lock()
	c.config.setCmd(poolConfig.Cmd)
	c.runSync.Unlock()
	logrus.Debugf("Setting cmd unlocked")

	logrus.Debugf("Cmd set")
	return nil
}

func (c *Pool) validate() error {
	duration, err := time.ParseDuration(c.config.getTimeout())
	if err != nil {
		return fmt.Errorf("Validating pool: parsing timeout: %v", err)
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
	cmd := c.config.getCmd()
	c.runSync.Unlock()
	logrus.Debugf("Pool run unlocked")
	return c.run(cmd)
}

func (c *Pool) run(cmd []string) error {
	if cmd == nil || len(cmd) == 0 {
		return fmt.Errorf("Pool run: cmd should be provided")
	}
	var wg sync.WaitGroup
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, os.Kill)

	wgErrors, errStrings := newErrorByChan()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	for _, host := range c.config.getHosts() {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			_, err := h.Run(ctx, cmd, dialerRunKindCombined)
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

running:
	for {
		select {
		case errStr := <-wgErrors:
			if errStr == nil {
				break running
			}
			errStrings = append(errStrings, *errStr)
		case <-exit:
			logrus.Info("Exit signal detected....trying to close properly...")
			cancel()
			<-wgErrors
			fmt.Printf("killed\n")
			return fmt.Errorf("Pool killed by user request: %v", ctx.Err())
		case <-ctx.Done():
			logrus.Errorf("Pool run context timeout: %s", c.config.getTimeout())
			<-wgErrors
			fmt.Printf("killed\n")
			return fmt.Errorf("Pool run context cancelled: %v", ctx.Err())
		}
	}

	if len(errStrings) > 0 {
		fmt.Printf("error\n")
		return fmt.Errorf("Pool run failed:\n%s", stringsToLines(errStrings))
	}
	fmt.Printf("ok\n")
	logrus.Debugf("Pool runned")
	return nil
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
