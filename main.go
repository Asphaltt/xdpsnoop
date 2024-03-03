// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -no-global-types xdpsnoop ./bpf/xdpsnoop.c -- -D__TARGET_ARCH_x86 -I./bpf/headers -Wno-address-of-packed-member

var flags struct {
	verbose bool
}

func init() {
	flag.BoolVar(&flags.verbose, "verbose", false, "verbose output")
	flag.Parse()
}

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	funcs, err := getFuncs()
	if err != nil {
		log.Fatalf("Failed to get available xdp install functions: %v", err)
	}

	spec, err := loadXdpsnoop()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	var obj xdpsnoopObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load and assign program: %v\n%+v", err, ve)
		} else {
			log.Fatalf("Failed to load and assign program: %v", err)
		}
	}
	defer obj.Close()

	for _, fn := range funcs {
		if kp, err := link.Kprobe(fn, obj.K_xdpInstall, nil); err != nil {
			log.Fatalf("Failed to attach kprobe to %s: %v", fn, err)
		} else {
			defer kp.Close()
			if flags.verbose {
				log.Printf("Attached kprobe to %s", fn)
			}
		}

		if krp, err := link.Kretprobe(fn, obj.KrXdpInstall, nil); err != nil {
			log.Fatalf("Failed to attach kretprobe to %s: %v", fn, err)
		} else {
			defer krp.Close()
			if flags.verbose {
				log.Printf("Attached kretprobe to %s", fn)
			}
		}
	}

	reader, err := perf.NewReader(obj.Events, 8192)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return outputEvents(ctx, reader)
	})

	if err := errg.Wait(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func outputEvents(ctx context.Context, reader *perf.Reader) error {
	log.Println("Listening for events...")

	var ev event
	for {
		record, err := reader.Read()
		if err != nil {
			if !errors.Is(err, perf.ErrClosed) {
				return fmt.Errorf("failed to read record: %v", err)
			}

			return nil
		}

		if record.LostSamples != 0 {
			log.Printf("Lost %d samples", record.LostSamples)
		}

		if err := ev.UnmarshalBinary(record.RawSample); err != nil {
			log.Printf("Failed to unmarshal event: %v", err)
			continue
		}

		ev.print()

		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}
