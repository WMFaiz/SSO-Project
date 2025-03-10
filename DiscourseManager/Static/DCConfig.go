package static

import (
	"fmt"
)

type Config struct {
	APIKey      string
	APIUsername string
	BaseURL     string
}

type Actions struct {
	ListAllUsers string
	NewUser      string
	PostTopic    string
	SiteInfo     string
	Topics       string
}

var DCConfig = Config{
	APIKey:      "YOUR_DISCOURSE_APIKEY",
	APIUsername: "YOUR_ADMIN_USENAME",
	BaseURL:     "https://your.host.org",
}

// APIs call without arg
var DCActions = Actions{
	ListAllUsers: DCConfig.BaseURL + "/admin/users/list/active.json",
	NewUser:      DCConfig.BaseURL + "/users.json",
	PostTopic:    DCConfig.BaseURL + "/posts.json",
	SiteInfo:     DCConfig.BaseURL + "/site.json",
	Topics:       DCConfig.BaseURL + "/latest.json",
}

// APIs call with arg
func (a *Actions) UserDetails(username string) string {
	return fmt.Sprintf("%s/u/%s.json", DCConfig.BaseURL, username)
}
