package lastpass

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"io/ioutil"
	"strconv"
	"fmt"
	"io"
	"encoding/xml"
	"bytes"
	"github.com/analogj/go-lastpass/security"

	"encoding/base64"
)

type Client struct {
	HttpClient *http.Client
	CookieJar http.CookieJar

	//session information
	Email string
	SessionId string
	Token string
	KeyIterationCount int
	Key []byte
}

type blob struct {
	bytes             []byte
	keyIterationCount int
}

const (
	loginEndpoint = "login.php"
	iterationsEndpoint = "iterations.php"
	getAccountsEndpoint = "getaccts.php"
)

func (c *Client) Init() error {
	if c.HttpClient == nil {
		jar, jerr := cookiejar.New(nil)
		if jerr != nil {
			return jerr
		}

		c.HttpClient = &http.Client{
			Jar: jar,
		}
	}

	return nil
}

func (c *Client)GetIterationCount(username string) (int, error) {


	res, err := c.HttpClient.PostForm(
		fmt.Sprintf("https://lastpass.com/%s", iterationsEndpoint),
		url.Values{
			"email": []string{username},
		})
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}
	count, err := strconv.Atoi(string(b))
	if err != nil {
		return 0, err
	}
	return count, nil
}


func (c *Client) Login(username, password string, multiFactor string) error {
	iterationCount, err := c.GetIterationCount(username)
	if err != nil {
		return err
	}
	return c.MakeSession(username, password, iterationCount, multiFactor)
}

func (c *Client)MakeSession(username, password string, iterationCount int, multiFactor string) error {
	vals := url.Values{
		"method":     []string{"mobile"},
		"web":        []string{"1"},
		"xml":        []string{"1"},
		"username":   []string{username},
		"hash":       []string{string(security.MakeHash(username, password, iterationCount))},
		"iterations": []string{fmt.Sprint(iterationCount)},
	}
	if multiFactor != "" {
		vals.Set("otp", multiFactor)
	}

	res, err := c.HttpClient.PostForm(fmt.Sprintf("https://lastpass.com/%s", loginEndpoint), vals)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	var response struct {
		SessionId string `xml:"sessionid,attr"`
		Token     string `xml:"token,attr"`
		ErrResp *struct {
			AttrAllowmultifactortrust string `xml:" allowmultifactortrust,attr"  json:",omitempty"`
			AttrCause                 string `xml:" cause,attr"  json:",omitempty"`
			AttrHidedisable           string `xml:" hidedisable,attr"  json:",omitempty"`
			AttrMessage               string `xml:" message,attr"  json:",omitempty"`
			AttrTempuid               string `xml:" tempuid,attr"  json:",omitempty"`
			AttrTrustexpired          string `xml:" trustexpired,attr"  json:",omitempty"`
			AttrTrustlabel            string `xml:" trustlabel,attr"  json:",omitempty"`
		} `xml:" error,omitempty" json:"error,omitempty"`
	}

	// read to bytes for debugging
	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return err
	}

	err = xml.NewDecoder(bytes.NewReader(b)).Decode(&response)
	if err != nil {
		return err
	}

	if response.ErrResp != nil {
		switch response.ErrResp.AttrCause {
		case "googleauthfailed", "googleauthrequired":
			return fmt.Errorf("googleauthfailed")
		case "unknownpassword":
			return fmt.Errorf("invalid password")
		case "yubikeyrestricted":
			return fmt.Errorf("yubikey restricted")
		case "unknownemail":
			return fmt.Errorf("invalid username or password")
		default:
			return fmt.Errorf("%s", response.ErrResp.AttrMessage)
		}
	}

	key := security.MakeKey(username, password, iterationCount)

	c.SessionId = response.SessionId
	c.Token = response.Token
	c.KeyIterationCount = iterationCount
	c.Key = key
	return nil
}


func (c *Client)GetRequest(endpoint string) (*blob, error) {

	u := &url.URL{
		Scheme: "https",
		Host:   "lastpass.com",
		Path:   endpoint,
	}

	u.RawQuery = (&url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{c.SessionId},
	}).Encode()

	res, err := c.HttpClient.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}

	//fmt.Println(string(b))
	if res.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("invalid password")
	}

	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	return &blob{b, c.KeyIterationCount}, nil
}