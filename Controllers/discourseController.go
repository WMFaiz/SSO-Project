package Controller

import (
	"Server/Utils"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

type DiscourseData struct {
	Email      string `json:"email"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	ExternalID string `json:"external_id"`
	Sso        string `json:"sso"`
	Sig        string `json:"sig"`
}

type DiscourseDataById struct {
	ID string `json:"id"`
}

type DiscourseResponse struct {
	TopicList struct {
		Topics []TopicData `json:"topics"`
	} `json:"topic_list"`
}

type TopicData struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	CreatedAt    string `json:"created_at"`
	Views        int    `json:"views"`
	ReplyCount   int    `json:"reply_count"`
	LastPostedAt string `json:"last_posted_at"`
	Blurb        string `json:"blurb"`
	Summary      string `json:"summary,omitempty"`
}

type PostResponse struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	CreatedAt    string `json:"created_at"`
	Views        int    `json:"views"`
	ReplyCount   int    `json:"reply_count"`
	LastPostedAt string `json:"last_posted_at"`
	Blurb        string `json:"blurb"`
	PostStream   struct {
		Posts []Post `json:"posts"`
	} `json:"post_stream"`
}

type Post struct {
	Raw    string `json:"raw"`
	Cooked string `json:"cooked"`
}

func (cntrlr *Controller) DiscourseFetchNews(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	//Setup Header
	//START
	//------------------------
	allowedOrigins := []string{
		"http://localhost:8080",
		"http://192.168.0.2:8080",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
	}

	origin := req.Header.Get("Origin")
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			res.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}

	if req.Method == http.MethodOptions {
		res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		res.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		res.Header().Set("Access-Control-Allow-Credentials", "true")
		res.WriteHeader(http.StatusOK)
		return
	}

	if req.Method != http.MethodGet {
		http.Error(res, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	//END
	//Setup Header
	//------------------------

	//Get data in config manager
	//START
	//------------------------
	config_apiKey, err := Utils.ConfigManager("DISCOURSE_PUBLIC_APIKEY")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}
	config_apiUser, err := Utils.ConfigManager("DISCOURSE_ADMIN_USERNAME")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}
	//Get data in config manager
	//START
	//------------------------

	//Get Discourse News
	//START
	//-------------------------
	client := &http.Client{Timeout: 10 * time.Second}
	apiReq, err := http.NewRequest(http.MethodGet, "https://your.host.org/latest.json?include_hidden=true", nil)
	if err != nil {
		http.Error(res, `{"error": "Failed to create request"}`, http.StatusInternalServerError)
		log.Println("Request Error:", err)
		return
	}

	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("Api-Key", config_apiKey)
	apiReq.Header.Set("Api-Username", config_apiUser)

	resp, err := client.Do(apiReq)
	if err != nil {
		http.Error(res, `{"error": "Failed to fetch news from Discourse"}`, http.StatusInternalServerError)
		log.Println("API Request Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(res, `{"error": "Failed to read response body"}`, http.StatusInternalServerError)
		log.Println("Read Response Error:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(res, fmt.Sprintf(`{"error": "Discourse API error: %s"}`, http.StatusText(resp.StatusCode)), resp.StatusCode)
		log.Printf("Discourse API Error (%d): %s", resp.StatusCode, string(body))
		return
	}

	var discourseData DiscourseResponse
	if err := json.Unmarshal(body, &discourseData); err != nil {
		http.Error(res, `{"error": "Invalid response from Discourse"}`, http.StatusInternalServerError)
		log.Println("JSON Decode Error:", err)
		return
	}

	var topics []TopicData
	for _, topic := range discourseData.TopicList.Topics {
		if topic.Blurb == "" {
			topicURL := fmt.Sprintf("https://your.host.org/t/%d.json", topic.ID)
			topicDetailResp, err := client.Get(topicURL)
			if err != nil {
				log.Printf("Failed to fetch topic %d: %v", topic.ID, err)
				continue
			}
			defer topicDetailResp.Body.Close()

			body, err := ioutil.ReadAll(topicDetailResp.Body)
			if err != nil {
				log.Printf("Failed to read response for topic %d: %v", topic.ID, err)
				continue
			}

			var postData PostResponse
			if err := json.Unmarshal(body, &postData); err != nil {
				log.Printf("Failed to decode topic %d: %v", topic.ID, err)
				continue
			}

			if len(postData.PostStream.Posts) > 0 {
				post := postData.PostStream.Posts[0].Cooked
				if len(post) > 500 {
					topic.Summary = post[:500] + "..."
				} else {
					topic.Summary = post
				}
			} else {
				topic.Summary = "(No summary available)"
			}
		} else {
			topic.Summary = topic.Blurb
		}

		topics = append(topics, topic)
	}

	responseJSON, err := json.Marshal(topics)
	if err != nil {
		http.Error(res, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		log.Println("JSON Encode Error:", err)
		return
	}
	//END
	//Get Discourse News
	//--------------------------

	//START
	//Output
	//-----------------------
	res.Header().Set("Content-Type", "application/json")
	res.Write(responseJSON)
	//END
	//Output
	//-----------------------
}

func (cntrlr *Controller) DiscourseFetchNewsById(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	//Setup Header
	//START
	//------------------------
	allowedOrigins := []string{
		"http://localhost:8080",
		"http://192.168.0.2:8080",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
	}

	origin := req.Header.Get("Origin")
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			res.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}

	if req.Method == http.MethodOptions {
		res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		res.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		res.Header().Set("Access-Control-Allow-Credentials", "true")
		res.WriteHeader(http.StatusOK)
		return
	}

	if req.Method != http.MethodGet {
		http.Error(res, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	//END
	//Setup Header
	//------------------------

	//Get data in config manager
	//START
	//------------------------
	config_apiKey, err := Utils.ConfigManager("DISCOURSE_PUBLIC_APIKEY")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}
	config_apiUser, err := Utils.ConfigManager("DISCOURSE_ADMIN_USERNAME")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}
	//Get data in config manager
	//START
	//------------------------

	//Get Discourse News
	//START
	//-------------------------
	paramTopicID := req.URL.Query().Get("id")
	if paramTopicID == "" {
		http.Error(res, `{"error": "Missing topic ID"}`, http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	apiURL := fmt.Sprintf("https://your.host.org/t/%s.json", paramTopicID)

	apiReq, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(res, `{"error": "Failed to create request"}`, http.StatusInternalServerError)
		log.Println("Request Error:", err)
		return
	}

	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("Api-Key", config_apiKey)
	apiReq.Header.Set("Api-Username", config_apiUser)

	resp, err := client.Do(apiReq)
	if err != nil {
		http.Error(res, `{"error": "Failed to fetch topic from Discourse"}`, http.StatusInternalServerError)
		log.Println("API Request Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(res, `{"error": "Failed to read response body"}`, http.StatusInternalServerError)
		log.Println("Read Response Error:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(res, fmt.Sprintf(`{"error": "Discourse API error: %s"}`, http.StatusText(resp.StatusCode)), resp.StatusCode)
		log.Printf("Discourse API Error (%d): %s", resp.StatusCode, string(body))
		return
	}

	var postData PostResponse
	if err := json.Unmarshal(body, &postData); err != nil {
		http.Error(res, `{"error": "Invalid response from Discourse"}`, http.StatusInternalServerError)
		log.Println("JSON Decode Error:", err)
		return
	}

	if len(postData.PostStream.Posts) == 0 {
		http.Error(res, `{"error": "No posts found for this topic"}`, http.StatusNotFound)
		return
	}

	firstPost := postData.PostStream.Posts[0].Cooked
	summary := postData.Blurb
	if summary == "" {
		if len(firstPost) > 500 {
			summary = firstPost[:500] + "..."
		} else {
			summary = firstPost
		}
	}

	topicData := TopicData{
		ID:           postData.ID,
		Title:        postData.Title,
		CreatedAt:    postData.CreatedAt,
		Views:        postData.Views,
		ReplyCount:   postData.ReplyCount,
		LastPostedAt: postData.LastPostedAt,
		Blurb:        postData.Blurb,
		Summary:      summary,
	}
	//END
	//Get Discourse News
	//--------------------------

	//START
	//Output
	//-----------------------
	responseJSON, err := json.Marshal(topicData)
	if err != nil {
		http.Error(res, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		log.Println("JSON Encode Error:", err)
		return
	}
	res.Header().Set("Content-Type", "application/json")
	res.Write(responseJSON)
	//END
	//Output
	//-----------------------
}

func (cntrlr *Controller) DiscourseSSO(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	//Setup Header
	//START
	//------------------------
	allowedOrigins := []string{
		"http://localhost:8080",
		"http://192.168.0.2:8080",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
	}

	origin := req.Header.Get("Origin")
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			res.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}

	if req.Method == http.MethodOptions {
		res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		res.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		res.Header().Set("Access-Control-Allow-Credentials", "true")
		res.WriteHeader(http.StatusOK)
		return
	}

	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(res, `{"error": "Method not allowed"}`)
		return
	}
	//END
	//Setup Header
	//------------------------

	//Data abstraction
	//START
	//------------------------
	var discourseData DiscourseData
	if err := json.NewDecoder(req.Body).Decode(&discourseData); err != nil || discourseData.Email == "" || discourseData.Username == "" || discourseData.Name == "" {
		http.Error(res, `{"error": "Invalid or missing payload fields"}`, http.StatusBadRequest)
		return
	}
	//END
	//Data abstraction
	//-------------------------

	//SSO Discourse
	//START
	//-------------------------
	form := url.Values{}
	form.Set("email", discourseData.Email)
	form.Set("external_id", discourseData.ExternalID)
	form.Set("username", discourseData.Username)
	form.Set("name", discourseData.Name)
	form.Set("sso", discourseData.Sso)
	form.Set("sig", discourseData.Sig)

	reqDiscourse, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:9096/YOUR_PATH/discourse/authorize/sso", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(res, "Failed to create OAuth request", http.StatusInternalServerError)
		return
	}
	reqDiscourse.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	respDiscourse, err := client.Do(reqDiscourse)
	if err != nil || respDiscourse.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(respDiscourse.Body)
		http.Error(res, fmt.Sprintf(`{"error": "OAuth server error: %s"}`, string(body)), http.StatusInternalServerError)
		return
	}
	defer respDiscourse.Body.Close()

	var discResponse map[string]interface{}
	if err := json.NewDecoder(respDiscourse.Body).Decode(&discResponse); err != nil {
		http.Error(res, `{"error": "Invalid response from OAuth2 server"}`, http.StatusInternalServerError)
		return
	}
	//END
	//SSO Discourse
	//--------------------------

	//START
	//Output
	//-----------------------
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	json.NewEncoder(res).Encode(discResponse)
	//END
	//Output
	//-----------------------
}
