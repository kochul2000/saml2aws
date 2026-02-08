package localbrowser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "localbrowser")

const defaultTimeout = 300 // seconds

// Client is a local browser based Identity Provider client.
// Unlike the Browser provider which uses Playwright (downloading its own browser),
// this provider uses the system's locally installed browser via Chrome DevTools Protocol.
// This allows reusing existing login sessions (cookies, etc.).
type Client struct {
	BrowserExecutablePath string
	BrowserUserDataDir    string
	Timeout               int
}

// New creates a new local browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		BrowserExecutablePath: idpAccount.BrowserExecutablePath,
		BrowserUserDataDir:    idpAccount.BrowserUserDataDir,
		Timeout:               idpAccount.Timeout,
	}, nil
}

// Validate validates the login details
func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {
	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}
	return nil
}

// Authenticate opens the local browser, navigates to the IDP login URL,
// and captures the SAML response via Chrome DevTools Protocol network interception.
func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	signinRe, err := signinRegex()
	if err != nil {
		return "", fmt.Errorf("failed to compile signin regex: %w", err)
	}

	timeout := cl.timeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	execPath := cl.findBrowser()
	if execPath == "" {
		return "", errors.New("could not find a local Chrome/Chromium/Edge browser; set browser_executable_path in your config")
	}
	logger.WithField("browser", execPath).Info("using local browser")

	// Build chromedp allocator options
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions-except", ""),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("no-first-run", true),
		chromedp.ExecPath(execPath),
	}

	// Use the user's existing browser profile to keep login sessions
	if cl.BrowserUserDataDir != "" {
		opts = append(opts, chromedp.UserDataDir(cl.BrowserUserDataDir))
		logger.WithField("user-data-dir", cl.BrowserUserDataDir).Info("using specified user data directory")
	} else {
		userDataDir := defaultUserDataDir(execPath)
		if userDataDir != "" {
			opts = append(opts, chromedp.UserDataDir(userDataDir))
			logger.WithField("user-data-dir", userDataDir).Info("using detected user data directory")
		}
		// If no user data dir is found, chromedp will use a temp directory
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(logger.Infof))
	defer taskCancel()

	// Channel to receive the SAML response
	samlCh := make(chan string, 1)

	// Enable Fetch API for request interception to capture SAML POST data
	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *fetch.EventRequestPaused:
			go func() {
				reqURL := e.Request.URL
				if signinRe.MatchString(reqURL) && e.Request.Method == "POST" {
					logger.WithField("url", reqURL).Info("captured SAML signin request")
					postData := getPostDataFromRequest(e.Request)
					if postData != "" {
						values, parseErr := url.ParseQuery(postData)
						if parseErr == nil {
							samlResp := values.Get("SAMLResponse")
							if samlResp != "" {
								select {
								case samlCh <- samlResp:
								default:
								}
							}
						}
					}
				}
				// Continue the request so the browser proceeds normally
				_ = chromedp.Run(taskCtx, fetch.ContinueRequest(e.RequestID))
			}()
		}
	})

	// Navigate to the login URL and enable Fetch interception
	logger.WithField("URL", loginDetails.URL).Info("opening local browser")

	if err := chromedp.Run(taskCtx,
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{
			{URLPattern: "*signin.aws.amazon.com/saml*", RequestStage: fetch.RequestStageRequest},
			{URLPattern: "*signin.amazonaws-us-gov.com/saml*", RequestStage: fetch.RequestStageRequest},
			{URLPattern: "*signin.amazonaws.cn/saml*", RequestStage: fetch.RequestStageRequest},
		}),
		chromedp.Navigate(loginDetails.URL),
	); err != nil {
		return "", fmt.Errorf("failed to navigate to login URL: %w", err)
	}

	logger.Info("waiting for SAML response (complete authentication in the browser)...")

	// Wait for the SAML response or timeout
	select {
	case samlResponse := <-samlCh:
		logger.Info("SAML response captured successfully")
		return samlResponse, nil
	case <-ctx.Done():
		return "", fmt.Errorf("timed out waiting for SAML response after %v", timeout)
	}
}

// getPostDataFromRequest extracts POST data from a network.Request.
// The cdproto library stores POST data in PostDataEntries (each entry has a Bytes field).
func getPostDataFromRequest(req *network.Request) string {
	if !req.HasPostData {
		return ""
	}
	if len(req.PostDataEntries) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, entry := range req.PostDataEntries {
		sb.WriteString(entry.Bytes)
	}
	return sb.String()
}

// signinRegex returns the regex for AWS SAML signin endpoints
func signinRegex() (*regexp.Regexp, error) {
	return regexp.Compile(`https://((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))/saml`)
}

// timeout returns the configured timeout as a time.Duration
func (cl *Client) timeout() time.Duration {
	t := cl.Timeout / 1000 // config is in milliseconds
	if t < 30 {
		t = defaultTimeout
	}
	return time.Duration(t) * time.Second
}

// findBrowser locates a Chrome/Chromium/Edge browser binary on the system
func (cl *Client) findBrowser() string {
	if cl.BrowserExecutablePath != "" {
		return cl.BrowserExecutablePath
	}

	candidates := browserCandidates()
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

// browserCandidates returns a list of browser binary names to search for
func browserCandidates() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"google-chrome-stable",
			"google-chrome",
			"chromium-browser",
			"chromium",
			"microsoft-edge-stable",
			"microsoft-edge",
			// WSL: try Windows browsers via /mnt/c
			"/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
			"/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe",
			"/mnt/c/Program Files/Microsoft/Edge/Application/msedge.exe",
			"/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
		}
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
	case "windows":
		return []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		}
	default:
		return []string{"google-chrome", "chromium", "chromium-browser"}
	}
}

// defaultUserDataDir returns the default user data directory for the detected browser.
// This enables reusing existing login sessions.
func defaultUserDataDir(execPath string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	lowerPath := strings.ToLower(execPath)

	switch {
	case strings.Contains(lowerPath, "chromium"):
		return home + "/.config/chromium"
	case strings.Contains(lowerPath, "google-chrome") || strings.Contains(lowerPath, "chrome.exe"):
		if runtime.GOOS == "linux" {
			return home + "/.config/google-chrome"
		}
	case strings.Contains(lowerPath, "microsoft-edge") || strings.Contains(lowerPath, "msedge"):
		if runtime.GOOS == "linux" {
			return home + "/.config/microsoft-edge"
		}
	}

	return ""
}
