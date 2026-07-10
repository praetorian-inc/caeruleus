package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/fuzz/corpus"
	"github.com/praetorian-inc/caeruleus/internal/fuzz/engine"
)

var fuzzReplayFlags struct {
	handle string
	uuid   string
	op     string
}

func newFuzzReplayCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "replay PATH",
		Short: "Re-send inputs from a saved corpus file or directory",
		Long: `Replay one or many saved inputs from a previous fuzz run. PATH may be:

  - a single .bin file (sends that one input once)
  - a directory (sends every .bin under it, in filename order)

Typical use is verifying a crash repro:

  caeruleus -b AA:BB:CC:DD:EE:FF fuzz replay fuzz-out-20260601/crashes/a1b2c3d4.bin

Replay prints one line per input:

  0xHND replay=<id> op=<op> resp=<opcode/disc/timeout> err=<code> live=<ok|fail> ms=<n>`,
		Args: cobra.ExactArgs(1),
		RunE: runFuzzReplay,
	}
	c.Flags().StringVarP(&fuzzReplayFlags.handle, "handle", "a", "", "target characteristic/descriptor handle")
	c.Flags().StringVarP(&fuzzReplayFlags.uuid, "uuid", "u", "", "target characteristic UUID (alternative to --handle)")
	c.Flags().StringVar(&fuzzReplayFlags.op, "op", "req", "write variant for replay: req | cmd")
	return c
}

func runFuzzReplay(cmd *cobra.Command, args []string) error {
	if fuzzReplayFlags.handle == "" && fuzzReplayFlags.uuid == "" {
		return fmt.Errorf("supply -a/--handle or -u/--uuid")
	}
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	op, ok := engine.ParseOp(fuzzReplayFlags.op)
	if !ok {
		return fmt.Errorf("--op: unknown variant %q", fuzzReplayFlags.op)
	}

	inputs, names, err := corpus.LoadFileOrDir(args[0])
	if err != nil {
		return fmt.Errorf("load %s: %w", args[0], err)
	}
	if len(inputs) == 0 {
		return fmt.Errorf("no .bin inputs under %s", args[0])
	}

	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	sess, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer sess.close()

	target, err := resolveChar(sess, fuzzReplayFlags.handle, fuzzReplayFlags.uuid)
	if err != nil {
		return err
	}
	h := &bluezHarness{
		addr:         addr,
		targetHandle: target.Handle,
		writeTimeout: time.Duration(root.timeout) * time.Second,
		noLiveness:   true,
		sess:         sess,
		targetPath:   target.Path,
	}

	for i, in := range inputs {
		t0 := time.Now()
		res := h.Write(context.Background(), op, in)
		elapsed := time.Since(t0).Milliseconds()
		fmt.Println(formatReplayLine(target.Handle, op, names[i], in, res, elapsed))
	}
	return nil
}

func formatReplayLine(handle uint16, op engine.Op, name string, in []byte, res engine.WriteResult, ms int64) string {
	resp := "ok"
	errCode := ""
	switch {
	case res.Resp.Disconnected:
		resp = "disconnect"
	case res.Resp.Timeout:
		resp = "timeout"
	case res.Resp.Opcode == 0x01:
		resp = "att_error"
		errCode = fmt.Sprintf(" err=0x%02x", res.Resp.ErrCode)
	case res.Resp.Opcode != 0:
		resp = fmt.Sprintf("0x%02x", res.Resp.Opcode)
	}
	transportErr := ""
	if res.Err != nil {
		transportErr = fmt.Sprintf(" transport_err=%q", res.Err.Error())
	}
	return fmt.Sprintf("0x%04x replay=%s op=%s len=%d resp=%s%s ms=%d%s",
		handle, name, op.String(), len(in), resp, errCode, ms, transportErr)
}
