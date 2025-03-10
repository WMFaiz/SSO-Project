package structs

type Topic struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	CreatedAt    string `json:"created_at"`
	Views        int    `json:"views"`
	ReplyCount   int    `json:"reply_count"`
	LastPostedAt string `json:"last_posted_at"`
}
