package lastpass

import (
	"bytes"
	"fmt"
)

type Account struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Url      string `json:"url"`
	Group    string `json:"group"`
	Notes    string `json:"notes"`
}


// GetAccounts returns all accounts in the LastPass vault
func (c *Client) GetAccounts() ([]*Account, error) {
	blob, err := c.GetRequest(getAccountsEndpoint)
	if err != nil {
		return nil, err
	}

	chunks, err := extractChunks(bytes.NewReader(blob.bytes), []uint32{chunkIdFromString("ACCT")})
	if err != nil {
		return nil, err
	}
	accountChunks := chunks[chunkIdFromString("ACCT")]
	accs := make([]*Account, len(accountChunks))

	for i, chunk := range accountChunks {
		account, err := parseAccount(bytes.NewReader(chunk), c.Key)
		if err != nil {
			return nil, err
		}
		accs[i] = account
	}
	return accs, nil
}

// GetAccount gets LastPass account by unique ID
// If not found, returns ErrAccountNotFound error
func (c *Client) GetAccount(id string) (*Account, error) {
	accs, err := c.Search(id, Id, CaseInsensitive)
	if err != nil {
		return nil, err
	} else if accs == nil || len(accs) == 0 {
		return nil, fmt.Errorf("account not found")
	}

	return accs[0], nil
}


// Search looks for LastPass accounts matching given args.
func (c *Client) Search(value string, field Field, method SearchMethod) ([]*Account, error) {
	accs, err := c.GetAccounts()
	if err != nil {
		return nil, err
	}

	matchedAccounts := []*Account{}

	matchFunc := matchFuncs[method]
	for _, acc := range accs {
		if matchFunc(getValue(*acc, field), value) {
			matchedAccounts = append(matchedAccounts, acc)
		}
	}

	return matchedAccounts, nil
}