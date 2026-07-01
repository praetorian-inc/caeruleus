package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

func newDisconnectCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "disconnect",
		Aliases: []string{"dc"},
		Short:   "Disconnect a peripheral and wait for Connected=false",
		Long: `Tells bluetoothd to tear down the LE link to -b BDADDR and waits up to a
few seconds for the disconnect to confirm. Useful for recovering when an
operation left the link half-open, or when you want to free the peripheral
for another client.`,
		RunE: runDisconnect,
	}
	c.Flags().IntVar(&disconnectFlags.waitSec, "wait", 3, "seconds to wait for Connected=false")
	return c
}

var disconnectFlags struct {
	waitSec int
}

func runDisconnect(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	c, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer c.Close()

	d := c.Device(addr)
	if !d.Exists() {
		fmt.Printf("%s unknown to bluetoothd (already cleared)\n", addr)
		return nil
	}
	connected, _ := d.Connected()
	if !connected {
		fmt.Printf("%s already disconnected\n", addr)
		return nil
	}
	if err := d.Disconnect(); err != nil {
		return fmt.Errorf("Disconnect: %w", err)
	}

	max := time.Duration(disconnectFlags.waitSec) * time.Second
	err = pollUntil(context.Background(), func() bool {
		conn, err := d.Connected()
		return err != nil || !conn
	}, 50*time.Millisecond, max)
	if err != nil {
		return fmt.Errorf("disconnect did not complete within %ds - bluetoothd still reports Connected=true", disconnectFlags.waitSec)
	}
	fmt.Printf("%s disconnected\n", addr)
	return nil
}
