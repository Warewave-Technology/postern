package sshd

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Bu dosya, SSH kanal-request payload'larını tiplere ayrıştırır. Broker
// (S1.5) bu tipleri relay kararları ve kayıt (S1.7) için kullanır.
//
// SSH wire formatı basittir: string = uint32 uzunluk + baytlar, sayılar
// big-endian uint32. ssh.Unmarshal bu formatı struct alanlarına eşler —
// alan SIRASI RFC 4254'teki payload sırasıyla birebir aynı olmalı.

// PtyRequest, "pty-req" payload'ı (RFC 4254 §6.2).
type PtyRequest struct {
	Term          string
	Columns, Rows uint32
	Width, Height uint32 // piksel cinsinden; genelde 0
	Modes         string // opaque terminal modes — parse etme, olduğu gibi ilet (Ek C.4)
}

// WindowChangeRequest, "window-change" payload'ı (RFC 4254 §6.7).
type WindowChangeRequest struct {
	Columns, Rows uint32
	Width, Height uint32
}

// ExecRequest, "exec" payload'ı (RFC 4254 §6.5).
type ExecRequest struct {
	Command string
}

// ErrShortPayload, payload beklenen alanları taşımayacak kadar kısaysa döner.
var ErrShortPayload = errors.New("sshd: request payload too short")

// ParsePty parses a "pty-req" payload.
func ParsePty(payload []byte) (PtyRequest, error) {
	var req PtyRequest

	err := ssh.Unmarshal(payload, &req)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrShortPayload, err)
	}
	return req, nil
}

// ParseWindowChange parses a "window-change" payload.
func ParseWindowChange(payload []byte) (WindowChangeRequest, error) {
	var req WindowChangeRequest

	err := ssh.Unmarshal(payload, &req)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrShortPayload, err)
	}

	return req, nil
}

// ParseExec parses an "exec" payload.
func ParseExec(payload []byte) (ExecRequest, error) {
	var req ExecRequest

	err := ssh.Unmarshal(payload, &req)
	if err != nil {
		return req, fmt.Errorf("%w: %v", ErrShortPayload, err)
	}

	return req, nil
}
