package types

type LogList struct {
	Operators []struct {
		Logs []struct {
			URL string `json:"url"`
		} `json:"logs"`
	} `json:"operators"`
}
