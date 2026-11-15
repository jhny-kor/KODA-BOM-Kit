package collect

import (
	iface "github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	"sync"
)

// Collect only warning counts, never raw third-party log messages that may contain source content.
type AuditLog struct {
	iface.Logger
	mu       sync.Mutex
	Warnings int
	Errors   int
}

func NewAuditLog() *AuditLog                              { return &AuditLog{Logger: discard.New()} }
func (l *AuditLog) Warnf(string, ...any)                  { l.Warn() }
func (l *AuditLog) Warn(...any)                           { l.mu.Lock(); l.Warnings++; l.mu.Unlock() }
func (l *AuditLog) Errorf(string, ...any)                 { l.Error() }
func (l *AuditLog) Error(...any)                          { l.mu.Lock(); l.Errors++; l.mu.Unlock() }
func (l *AuditLog) WithFields(...any) iface.MessageLogger { return l }
func (l *AuditLog) Nested(...any) iface.Logger            { return l }
