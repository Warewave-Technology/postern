package upstream

import "testing"

// Close'un nil-guard sözleşmesi: nil *Conn ya da nil client üzerinde Close
// çağırmak panik DEĞİL, sessiz no-op olmalı — defer'lı kullanımda hata
// yollarında Conn yarım kurulmuş olabilir.
func TestConnCloseNilSafe(t *testing.T) {
	t.Run("nil Conn", func(t *testing.T) {
		var c *Conn
		if err := c.Close(); err != nil {
			t.Fatalf("nil Conn.Close() nil dönmeli; gelen: %v", err)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		c := &Conn{}
		if err := c.Close(); err != nil {
			t.Fatalf("bos Conn.Close() nil dönmeli; gelen: %v", err)
		}
	})
}
