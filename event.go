// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Leon Hwang.

package main

import (
	"fmt"
	"log"
	"unsafe"
)

type event struct {
	Ifindex uint32
	Ifname  [16]byte
	Retval  int32
	Errmsg  [64]byte
	ProgID  uint32
	Prog    [16]byte

	IsDevAttach int8
	Pad         [3]uint8
}

const __sizeof_event = int(unsafe.Sizeof(event{}))

func (e *event) UnmarshalBinary(data []byte) error {
	if len(data) < int(__sizeof_event) {
		return fmt.Errorf("invalid data length: %d", len(data))
	}

	buf := unsafe.Slice((*byte)(unsafe.Pointer(e)), __sizeof_event)
	copy(buf, data)
	return nil
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (e *event) printInstall() {
	if e.Retval == 0 {
		log.Printf("Installed XDP to ifindex=%d ifname=%s bpf_prog_id=%d bpf_prog_name=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]), e.ProgID, nullStr(e.Prog[:]))
	} else {
		log.Printf("Failed to install XDP to ifindex=%d ifname=%s bpf_prog_id=%d bpf_prog_name=%s error=%d errmsg=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]), e.ProgID, nullStr(e.Prog[:]), e.Retval, nullStr(e.Errmsg[:]))
	}
}

func (e *event) printUninstall() {
	if e.Retval == 0 {
		log.Printf("Uninstalled XDP from ifindex=%d ifname=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]))
	} else {
		log.Printf("Failed to remove XDP from ifindex=%d ifname=%s error=%d errmsg=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]), e.Retval, nullStr(e.Errmsg[:]))
	}
}

func (e *event) printInstallInfo() {
	if e.ProgID == 0 {
		e.printUninstall()
	} else {
		e.printInstall()
	}
}

func (e *event) printDevAttach() {
	if e.Retval == 0 {
		log.Printf("Attached XDP to ifindex=%d ifname=%s bpf_prog_id=%d bpf_prog_name=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]), e.ProgID, nullStr(e.Prog[:]))
	} else {
		log.Printf("Failed to attach XDP to ifindex=%d ifname=%s bpf_prog_id=%d bpf_prog_name=%s error=%d errmsg=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]), e.ProgID, nullStr(e.Prog[:]), e.Retval, nullStr(e.Errmsg[:]))
	}
}

func (e *event) printDevDetach() {
	if e.Retval == 0 {
		log.Printf("Detached XDP from ifindex=%d ifname=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]))
	} else {
		log.Printf("Failed to detach XDP from ifindex=%d ifname=%s error=%d errmsg=%s\n",
			e.Ifindex, nullStr(e.Ifname[:]), e.Retval, nullStr(e.Errmsg[:]))
	}
}

func (e *event) printAttachInfo() {
	if e.ProgID != 0 {
		e.printDevAttach()
	} else {
		e.printDevDetach()
	}
}

func (e *event) print() {
	if e.IsDevAttach != 0 {
		e.printAttachInfo()
	} else {
		e.printInstallInfo()
	}
}
