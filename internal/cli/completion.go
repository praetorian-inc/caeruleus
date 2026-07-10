package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// newCompletionCmd replaces cobra's built-in completion command. The default
// one's install instructions write to ${fpath[1]} / a system directory, which
// is root-owned on most distros (and `sudo cmd > file` still fails, since the
// redirect runs as the user). These instructions install to a user-writable
// location with no sudo.
func newCompletionCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate a shell completion script",
		Long: `Generate the shell completion script for caeruleus.

Quickest (current shell only):
  source <(caeruleus completion bash)     # or: zsh, fish

Install for every new session (user-writable, no sudo):

bash:
  mkdir -p ~/.local/share/bash-completion/completions
  caeruleus completion bash > ~/.local/share/bash-completion/completions/caeruleus

zsh:
  mkdir -p ~/.zsh/completions
  caeruleus completion zsh > ~/.zsh/completions/_caeruleus
  # add these to ~/.zshrc once (order matters - fpath before compinit):
  #   fpath=(~/.zsh/completions $fpath)
  #   autoload -U compinit && compinit

fish:
  caeruleus completion fish > ~/.config/fish/completions/caeruleus.fish

Start a new shell afterwards for the change to take effect.`,
		Args:                  cobra.ExactValidArgs(1),
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
	return c
}
