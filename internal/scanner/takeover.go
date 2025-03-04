package scanner

import (
	"io"
	"net/http"
	"strings"

	"github.com/fkr00t/subcollector/internal/models"
)

// TakeoverPatterns is a map of patterns used to detect potential subdomain takeovers
// Each entry represents a service and a string pattern that indicates vulnerability
var TakeoverPatterns = map[string]string{
	// Cloud storage
	"aws":                  "NoSuchBucket",
	"aws_s3":               "The specified bucket does not exist",
	"azure":                "The specified container does not exist", // Updated from "The specified blob does not exist"
	"azure_blob":           "404 The specified container does not exist",
	"google_cloud_storage": "The specified bucket does not exist", // Updated from "The requested URL was not found on this server"
	"digitalocean_spaces":  "NoSuchBucket",
	"backblaze_b2":         "No such bucket",                       // Added
	"oracle_cloud":         "The bucket does not exist.",           // Added
	"alibaba_cloud_oss":    "The specified bucket does not exist.", // Added
	"tencent_cloud_cos":    "The specified bucket does not exist.", // Added
	"ibm_cloud_storage":    "The specified bucket does not exist.", // Added

	// Hosting platforms
	"github":       "There isn't a GitHub Pages site here",
	"github_pages": "Page not found",
	"heroku":       "No such app",
	"pantheon":     "The gods are wise, but do not know of this site",
	"acquia":       "The site you were looking for couldn't be found",
	"ghost":        "The thing you were looking for is no longer here, or never was",
	"netlify":      "Not found - Request ID",
	"vercel":       "The deployment could not be found",
	"firebase":     "This site is not currently connected to Firebase",

	// E-commerce
	"shopify":     "Sorry, this shop is currently unavailable",
	"bigcommerce": "This store is unavailable",
	"wix":         "This domain is registered, but the owner hasn't connected it to a Wix site yet",
	"squarespace": "You're in the right place, but we can't find the page you're looking for",

	// CDNs
	"fastly":     "Fastly error: unknown domain",
	"cloudfront": "The request could not be satisfied",
	"akamai":     "Reference",
	"cloudflare": "DNS points to prohibited IP",

	// CMS
	"wordpress": "Do you want to register",
	"drupal":    "The requested page could not be found",
	"joomla":    "It looks like there's a server configuration issue",

	// Productivity & Support
	"teamwork":  "Oops - We didn't find your site",
	"helpjuice": "We could not find what you're looking for",
	"helpscout": "No settings were found for this company",
	"zendesk":   "Help Center Closed",
	"freshdesk": "Oops, this help center doesn't exist",
	"intercom":  "This page is reserved for",

	// Miscellaneous
	"cargo":       "The specified Cargo site could not be found",
	"feedpress":   "The feed has not been found",
	"surge":       "project not found",
	"webflow":     "The page you are looking for doesn't exist or has been moved",
	"jazzhr":      "This account no longer active",
	"statuspage":  "You are being redirected",
	"uservoice":   "This UserVoice subdomain is currently available",
	"thinkific":   "You may have typed the address incorrectly",
	"canny":       "Company Not Found",
	"pingdom":     "Sorry, couldn't find the status page",
	"tilda":       "Please renew your subscription",
	"unbounce":    "The requested URL was not found on this server",
	"smartjob":    "Job Board Is Unavailable",
	"readme":      "Project doesnt exist... yet!",
	"getresponse": "This landing page is unavailable or doesn't exist",
}

// CheckTakeover checks if a subdomain is vulnerable to takeover
// Sends an HTTP request and checks for patterns indicating potential takeover
func CheckTakeover(client *http.Client, result *models.SubdomainResult) {
	resp, err := client.Get("http://" + result.Subdomain)
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			for service, pattern := range TakeoverPatterns {
				if strings.Contains(string(body), pattern) {
					result.Takeover = service
					break
				}
			}
		}
	}
}
