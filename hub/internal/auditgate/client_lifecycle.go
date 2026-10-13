package auditgate

// CloseIdleConnections releases reusable connections owned by this client.
// It does not interrupt in-flight exact-record requests.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}
