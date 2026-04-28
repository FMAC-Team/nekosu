package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"
	"nekosu/ncore/kmod"
)

func main() {
	cmd := &cli.Command{
		Name:  "ncore",
		Usage: "nekosu userspace tools.",
		Commands: []*cli.Command{
			{
				Name:      "load",
				Usage:     "load kernel module",
				ArgsUsage: "<path>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() == 0 {
						return fmt.Errorf("path required")
					}
					return kmod.Load(cmd.Args().First())
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
