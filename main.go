package main

import (
	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

func main() {
	sdk.ServeWithStandalone(&GitHubPlugin{}, nil)
}
