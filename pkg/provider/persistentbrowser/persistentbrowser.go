package persistentbrowser

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "persistentbrowser")

const defaultTimeout float64 = 300000

// Client client for persistent browser based Identity Provider
type Client struct {
	ProfileDir            string
	BrowserType           string
	BrowserExecutablePath string
	Headless              bool
	BrowserDriverDir      string
	Timeout               int
	BrowserAutoFill       bool
}

// New create new PersistentBrowser client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		ProfileDir:            idpAccount.BrowserProfileDir,
		BrowserType:           strings.ToLower(idpAccount.BrowserType),
		BrowserExecutablePath: idpAccount.BrowserExecutablePath,
		Headless:              idpAccount.Headless,
		BrowserDriverDir:      idpAccount.BrowserDriverDir,
		Timeout:               idpAccount.Timeout,
		BrowserAutoFill:       idpAccount.BrowserAutoFill,
	}, nil
}

// Validate validates the login details
func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {
	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}
	return nil
}

// Authenticate performs SAML authentication using a persistent browser profile
func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	runOptions := playwright.RunOptions{}
	if cl.BrowserDriverDir != "" {
		runOptions.DriverDirectory = cl.BrowserDriverDir
	}

	if loginDetails.DownloadBrowser {
		if err := playwright.Install(&runOptions); err != nil {
			return "", err
		}
	}

	pw, err := playwright.Run(&runOptions)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := pw.Stop(); err != nil {
			logger.Info("Error when stopping playwright", err)
		}
	}()

	// Determine browser type
	browserType := pw.Chromium
	if cl.BrowserType == "firefox" {
		browserType = pw.Firefox
	} else if cl.BrowserType == "webkit" {
		browserType = pw.WebKit
	}

	// Resolve persistent profile directory
	profileDir, err := resolveProfileDir(cl.ProfileDir)
	if err != nil {
		return "", err
	}

	logger.WithField("profileDir", profileDir).Info("using persistent browser profile")

	// Build launch options for persistent context
	persistentOpts := playwright.BrowserTypeLaunchPersistentContextOptions{
		Headless: playwright.Bool(cl.Headless),
	}

	// Set browser channel (chrome, msedge, etc.)
	if cl.BrowserType != "" && cl.BrowserType != "chromium" && cl.BrowserType != "firefox" && cl.BrowserType != "webkit" {
		persistentOpts.Channel = playwright.String(cl.BrowserType)
	}

	// Set executable path if configured
	if cl.BrowserExecutablePath != "" {
		persistentOpts.ExecutablePath = playwright.String(cl.BrowserExecutablePath)
	}

	// Launch persistent context - profile directory preserves all cookies/sessions
	context, err := browserType.LaunchPersistentContext(profileDir, persistentOpts)
	if err != nil {
		return "", fmt.Errorf("failed to launch persistent browser context: %w", err)
	}
	defer func() {
		logger.Info("closing browser context (profile saved automatically)")
		if err := context.Close(); err != nil {
			logger.Info("Error when closing context", err)
		}
	}()

	page, err := context.NewPage()
	if err != nil {
		return "", err
	}

	return getSAMLResponse(page, loginDetails, cl)
}

var getSAMLResponse = func(page playwright.Page, loginDetails *creds.LoginDetails, client *Client) (string, error) {
	var data string
	var dataErr error

	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	signinRe, err := signinRegex()
	if err != nil {
		return "", err
	}

	// Channel to signal when SAML response is captured during navigation.
	// This handles the case where the user is already logged in and the IDP
	// redirects through the SAML endpoint to the AWS console. Without this,
	// page.Goto blocks waiting for the AWS console to fully load.
	samlCaptured := make(chan struct{}, 1)

	page.OnRequest(func(request playwright.Request) {
		if signinRe.Match([]byte(request.URL())) {
			data, dataErr = request.PostData()
			select {
			case samlCaptured <- struct{}{}:
			default:
			}
		}
	})

	// Run navigation in a goroutine - it may block on redirects when already logged in
	navDone := make(chan error, 1)
	go func() {
		_, err := page.Goto(loginDetails.URL)
		navDone <- err
	}()

	// Wait for either SAML response capture or navigation to complete
	select {
	case <-samlCaptured:
		logger.Info("SAML response captured during navigation (already logged in)")
	case err := <-navDone:
		if err != nil && data == "" {
			return "", err
		}
	}

	if data == "" {
		if client.BrowserAutoFill {
			err := autoFill(page, loginDetails)
			if err != nil {
				logger.Error("error when auto filling", err)
			}
		}

		logger.Info("waiting for SAML response (complete login in browser if needed)...")
		r, err := page.ExpectRequest(signinRe, nil, client.expectRequestTimeout())
		if err != nil {
			logger.Error(err)
		}
		data, dataErr = r.PostData()
	}
	if dataErr != nil {
		return "", dataErr
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}

	return values.Get("SAMLResponse"), nil
}

var autoFill = func(page playwright.Page, loginDetails *creds.LoginDetails) error {
	passwordField := page.Locator("input[type='password']")
	err := passwordField.WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateVisible,
	})
	if err != nil {
		return err
	}

	err = passwordField.Fill(loginDetails.Password)
	if err != nil {
		return err
	}

	keyboard := page.Keyboard()

	err = keyboard.Press("Shift+Tab")
	if err != nil {
		return err
	}

	err = keyboard.InsertText(loginDetails.Username)
	if err != nil {
		return err
	}

	submitLocator := page.Locator("form", playwright.PageLocatorOptions{
		Has: passwordField,
	}).Locator("[type='submit']")
	count, err := submitLocator.Count()
	if err != nil {
		return err
	}

	if count > 0 {
		return submitLocator.Click()
	} else {
		_, err := page.Evaluate(`document.querySelector('input[type="password"]').form.submit()`, nil)
		return err
	}
}

func signinRegex() (*regexp.Regexp, error) {
	return regexp.Compile(`https:\/\/((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))\/saml`)
}

func (cl *Client) expectRequestTimeout() playwright.PageExpectRequestOptions {
	timeout := float64(cl.Timeout)
	if timeout < 30000 {
		timeout = defaultTimeout
	}
	return playwright.PageExpectRequestOptions{Timeout: &timeout}
}

// resolveProfileDir determines the persistent profile directory
func resolveProfileDir(configured string) (string, error) {
	if configured != "" {
		if err := os.MkdirAll(configured, 0755); err != nil {
			return "", fmt.Errorf("could not create profile directory %s: %w", configured, err)
		}
		return configured, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	profileDir := filepath.Join(home, ".aws", "saml2aws", "persistentbrowser-profile")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return "", fmt.Errorf("could not create profile directory %s: %w", profileDir, err)
	}

	return profileDir, nil
}

