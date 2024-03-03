// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/btf"
)

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func getAllKmods() ([]string, error) {
	var kmods []string
	files, err := os.ReadDir("/sys/kernel/btf")
	if err != nil {
		return nil, fmt.Errorf("failed to read /sys/kernel/btf: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && file.Name() != "vmlinux" {
			kmods = append(kmods, file.Name())
		}
	}

	return kmods, nil
}

func getKmodIter(kmod string, spec *btf.Spec) (*btf.TypesIterator, error) {
	fpath := filepath.Join("/sys/kernel/btf", kmod)
	fd, err := os.Open(fpath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", fpath, err)
	}
	defer fd.Close()

	kmodSpec, err := btf.LoadSplitSpecFromReader(fd, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to load split spec from %s: %v", fpath, err)
	}

	return kmodSpec.Iterate(), nil
}

func checkFuncParam(p btf.FuncParam, structName string) bool {
	if ptr, ok := p.Type.(*btf.Pointer); ok {
		if strct, ok := ptr.Target.(*btf.Struct); ok {
			if strct.Name == structName {
				return true
			}
		}
	}
	return false
}

func getFuncs() ([]string, error) {
	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	kmods, err := getAllKmods()
	if err != nil {
		return nil, fmt.Errorf("failed to get all kmods: %v", err)
	}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel btf spec: %v", err)
	}

	var funcs []string

	iters := []*btf.TypesIterator{spec.Iterate()}

	for _, kmod := range kmods {
		kmodIter, err := getKmodIter(kmod, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to get kmod iter: %v", err)
		}

		iters = append(iters, kmodIter)
	}

	for _, iter := range iters {
		for iter.Next() {
			typ := iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := fn.Name

			availableFnName := fnName
			if _, ok := availableFuncs[availableFnName]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			if len(fnProto.Params) != 2 {
				continue
			}

			if checkFuncParam(fnProto.Params[0], "net_device") && checkFuncParam(fnProto.Params[1], "netdev_bpf") {
				funcs = append(funcs, fnName)
			}
		}
	}

	return funcs, nil
}
