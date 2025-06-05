package github

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"newtowner/internal/util"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"
)

const (
	newtownerWorkflowFileName  = "newtowner_github_http_check.yml"
	githubWorkflowURLBatchSize = 50
)

type URLCheckResult struct {
	URL             string
	Error           string
	DirectRequest   util.RequestDetails
	ProviderRequest util.RequestDetails
	Comparison      util.ComparisonResult
	PotentialBypass bool
	BypassReason    string

	ProviderActionDetails struct {
		RunID        int64
		ArtifactName string
		WorkflowPath string
		RunnerIP     string
		RunnerGeo    string
	}
	TargetHostname   string
	TargetResolvedIP string
	TargetGeoCountry string
	TargetGeoRegion  string
}

func (r URLCheckResult) GetURL() string {
	return r.URL
}

func (r URLCheckResult) GetTargetHostname() string {
	return r.TargetHostname
}

func (r URLCheckResult) GetTargetResolvedIP() string {
	return r.TargetResolvedIP
}

func (r URLCheckResult) GetTargetGeoCountry() string {
	return r.TargetGeoCountry
}

func (r URLCheckResult) GetTargetGeoRegion() string {
	return r.TargetGeoRegion
}

func (r URLCheckResult) GetProcessingError() string {
	return r.Error
}

func (r URLCheckResult) GetDirectRequestDetails() util.RequestDetails {
	return r.DirectRequest
}

func (r URLCheckResult) GetDirectDisplayName() string {
	return "Direct Request Details"
}

func (r URLCheckResult) GetProviderRequestDetails() util.RequestDetails {
	return r.ProviderRequest
}

func (r URLCheckResult) GetProviderDisplayName() string {
	return "GitHub Action Request"
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.ProviderActionDetails.RunID == 0 {
		return "Workflow Run ID: N/A (trigger or monitoring failed)"
	}
	return fmt.Sprintf("Workflow Run ID: %d", r.ProviderActionDetails.RunID)
}

func (r URLCheckResult) GetComparisonResult() util.ComparisonResult {
	return r.Comparison
}
func (r URLCheckResult) IsPotentialBypass() bool {
	return r.PotentialBypass
}

func (r URLCheckResult) GetBypassReason() string {
	return r.BypassReason
}

func (r URLCheckResult) ShouldSkipBodyDiff() bool {
	return r.Error != "" || r.DirectRequest.Error != "" || r.ProviderRequest.Error != ""
}

// Provider implements the Newtowner provider interface for GitHub Actions.
type Provider struct {
	client           *github.Client
	Owner            string // GitHub repository owner (user or organization)
	Repo             string // GitHub repository name
	WorkflowFileName string // Set internally to newtownerWorkflowFileName
	WorkflowID       int64  // Added to store the ID of the workflow
	DefaultBranch    string // Default branch to trigger workflow on e.g. "main"
}

// NewProvider creates and initializes a new GitHub Provider.
// workflowFile parameter is removed, uses internal constant newtownerWorkflowFileName.
func NewProvider(ctx context.Context, pat, owner, repo, defaultBranch string) (*Provider, error) {
	if pat == "" {
		return nil, fmt.Errorf("GitHub Personal Access Token (PAT) is required")
	}
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("GitHub owner and repo are required")
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: pat},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	if defaultBranch == "" {
		defaultBranch = "main" // Default to main if not specified
		log.Printf("Default branch for GitHub workflow not specified, using: %s", defaultBranch)
	}

	tempProvider := &Provider{
		client:           client,
		Owner:            owner,
		Repo:             repo,
		WorkflowFileName: newtownerWorkflowFileName,
	}

	workflowID, err := tempProvider.getWorkflowIDByName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow ID for '%s': %w", newtownerWorkflowFileName, err)
	}
	log.Printf("Found Workflow ID %d for %s", workflowID, newtownerWorkflowFileName)

	log.Printf("GitHub Provider initialized for %s/%s, workflow ID: %d (file: %s) on branch %s", owner, repo, workflowID, newtownerWorkflowFileName, defaultBranch)

	return &Provider{
		client:           client,
		Owner:            owner,
		Repo:             repo,
		WorkflowFileName: newtownerWorkflowFileName,
		WorkflowID:       workflowID,
		DefaultBranch:    defaultBranch,
	}, nil
}

// getWorkflowIDByName fetches the ID of a workflow by its filename.
func (p *Provider) getWorkflowIDByName(ctx context.Context) (int64, error) {
	workflows, _, err := p.client.Actions.ListWorkflows(ctx, p.Owner, p.Repo, &github.ListOptions{PerPage: 100})
	if err != nil {
		return 0, fmt.Errorf("listing workflows for %s/%s: %w", p.Owner, p.Repo, err)
	}

	for _, wf := range workflows.Workflows {
		workflowFilePath := wf.GetPath()
		// Extract filename from path, e.g., ".github/workflows/file.yml" -> "file.yml"
		parts := strings.Split(workflowFilePath, "/")
		fileNameInRepo := ""
		if len(parts) > 0 {
			fileNameInRepo = parts[len(parts)-1]
		}

		if fileNameInRepo == p.WorkflowFileName {
			log.Printf("Found matching workflow: ID=%d, Name='%s', Path='%s'", wf.GetID(), wf.GetName(), wf.GetPath())
			return wf.GetID(), nil
		}
	}

	return 0, fmt.Errorf("workflow with filename '%s' not found in %s/%s. Found %d workflows", p.WorkflowFileName, p.Owner, p.Repo, len(workflows.Workflows))
}

// CheckURLs performs checks for the given URLs using GitHub Actions.
func (p *Provider) CheckURLs(urls []string) ([]URLCheckResult, error) {
	var allResults []URLCheckResult
	ctx := context.Background()

	if len(urls) == 0 {
		return allResults, nil
	}

	allResults = make([]URLCheckResult, len(urls))
	resultsMap := make(map[string]*URLCheckResult)

	for i, rawURL := range urls {
		allResults[i] = URLCheckResult{URL: rawURL}
		result := &allResults[i]
		resultsMap[rawURL] = result

		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			result.Error = fmt.Sprintf("Error parsing URL: %v", err)
			log.Printf("[GitHub DEBUG] URL: %s - Initial population: Error parsing URL: %v", rawURL, err)
		} else {
			result.TargetHostname = parsedURL.Hostname()
		}

		log.Printf("[GitHub] Making direct request to %s", rawURL)
		result.DirectRequest = util.MakeHTTPRequest(ctx, "GET", rawURL, false)
		if result.DirectRequest.Error != "" {
			log.Printf("[GitHub] Direct request error for %s: %s", rawURL, result.DirectRequest.Error)
		}

		if result.TargetHostname != "" {
			geoLoc, resolvedIP, geoErr := util.ResolveHostAndGetGeoLocation(result.TargetHostname)
			if geoErr == nil {
				result.TargetResolvedIP = resolvedIP.String()
				result.TargetGeoCountry = geoLoc.CountryCode
				result.TargetGeoRegion = geoLoc.RegionName
			} else {
				log.Printf("[GitHub] Warning: Could not get GeoIP for %s: %v", result.TargetHostname, geoErr)
			}
		}
		log.Printf("[GitHub DEBUG] URL: %s - After direct/GeoIP: Error='%s', DirectStatus=%d, TargetHost='%s', ResolvedIP='%s'", rawURL, result.Error, result.DirectRequest.StatusCode, result.TargetHostname, result.TargetResolvedIP)
	}

	var validURLsForWorkflow []string
	for _, r := range allResults {
		if r.Error == "" && r.TargetHostname != "" {
			validURLsForWorkflow = append(validURLsForWorkflow, r.URL)
		}
	}

	if len(validURLsForWorkflow) == 0 {
		log.Printf("[GitHub] No valid URLs with successfully parsed hostnames to process via workflow.")
		return allResults, nil
	}

	for i := 0; i < len(validURLsForWorkflow); i += githubWorkflowURLBatchSize {
		end := i + githubWorkflowURLBatchSize
		if end > len(validURLsForWorkflow) {
			end = len(validURLsForWorkflow)
		}
		currentBatchURLs := validURLsForWorkflow[i:end]

		log.Printf("[GitHub] Processing batch %d/%d, URLs: %d. Batch URLs: %v", (i/githubWorkflowURLBatchSize)+1, (len(validURLsForWorkflow)+githubWorkflowURLBatchSize-1)/githubWorkflowURLBatchSize, len(currentBatchURLs), currentBatchURLs)

		// 1. Trigger GitHub Actions Workflow for the current batch of URLs
		batchTargetURL := strings.Join(currentBatchURLs, ",")
		sanitizedBatchNamePart := util.SanitizeFilename(fmt.Sprintf("batch-%d-urls-%d", len(currentBatchURLs), time.Now().Unix()))
		if len(sanitizedBatchNamePart) > 30 { // Shorter to accommodate full tag
			sanitizedBatchNamePart = sanitizedBatchNamePart[:30]
		}
		runIDTag := fmt.Sprintf("%s-%d", sanitizedBatchNamePart, time.Now().UnixNano())

		dispatchOpts := github.CreateWorkflowDispatchEventRequest{
			Ref: p.DefaultBranch,
			Inputs: map[string]interface{}{
				"target_url": batchTargetURL,
				"run_id_tag": runIDTag,
			},
		}

		log.Printf("[GitHub] Triggering workflow ID %d for batch with tag: %s (%s)", p.WorkflowID, runIDTag, batchTargetURL)
		_, dispatchErr := p.client.Actions.CreateWorkflowDispatchEventByID(ctx, p.Owner, p.Repo, p.WorkflowID, dispatchOpts)
		if dispatchErr != nil {
			dispatchErrorMsg := fmt.Sprintf("Failed to trigger GitHub workflow ID %d for batch (tag %s): %v", p.WorkflowID, runIDTag, dispatchErr)
			log.Printf("[GitHub] %s", dispatchErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok && res.Error == "" {
					res.Error = dispatchErrorMsg
				}
			}
			continue // Move to the next batch or finish if this was the last one
		}

		// 2. Poll for Workflow Completion for the current batch
		log.Printf("[GitHub] Waiting for workflow run (tag '%s') to complete...", runIDTag)
		workflowRun, pollErr := p.pollForWorkflowRun(ctx, runIDTag)
		if pollErr != nil {
			pollErrorMsg := fmt.Sprintf("Error waiting for workflow run (tag %s): %v", runIDTag, pollErr)
			log.Printf("[GitHub] %s", pollErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok && res.Error == "" {
					res.Error = pollErrorMsg
				}
			}
			continue
		}

		providerDetailsForBatch := struct {
			RunID        int64
			ArtifactName string
			WorkflowPath string
		}{
			RunID:        workflowRun.GetID(),
			ArtifactName: fmt.Sprintf("newtowner-check-result-%s", runIDTag),
			WorkflowPath: p.WorkflowFileName,
		}

		log.Printf("[GitHub] Workflow run %d (tag %s) completed with status: %s, conclusion: %s",
			workflowRun.GetID(), runIDTag, workflowRun.GetStatus(), workflowRun.GetConclusion())

		if workflowRun.GetStatus() != "completed" || workflowRun.GetConclusion() != "success" {
			workflowErrorMsg := fmt.Sprintf("Workflow run %d (tag %s) did not complete successfully. Status: %s, Conclusion: %s. Logs: %s",
				workflowRun.GetID(), runIDTag, workflowRun.GetStatus(), workflowRun.GetConclusion(), workflowRun.GetHTMLURL())
			log.Printf("[GitHub ERROR] %s", workflowErrorMsg) // Changed to ERROR for more visibility
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = workflowErrorMsg
					}
					res.ProviderActionDetails.RunID = providerDetailsForBatch.RunID
					res.ProviderActionDetails.WorkflowPath = providerDetailsForBatch.WorkflowPath
					res.ProviderActionDetails.ArtifactName = providerDetailsForBatch.ArtifactName
				}
			}
			continue
		}

		// 3. Download and Parse Artifacts for the current batch
		log.Printf("[GitHub] Downloading artifact: %s for workflow run %d (tag %s)", providerDetailsForBatch.ArtifactName, workflowRun.GetID(), runIDTag)
		providerActionResults, artifactErr := p.downloadAndParseArtifactsBatch(ctx, workflowRun.GetID(), providerDetailsForBatch.ArtifactName)
		if artifactErr != nil {
			artifactErrorMsg := fmt.Sprintf("Failed to download/parse artifact for batch (run %d, artifact %s, tag %s): %v",
				workflowRun.GetID(), providerDetailsForBatch.ArtifactName, runIDTag, artifactErr)
			log.Printf("[GitHub ERROR] %s", artifactErrorMsg) // Changed to ERROR
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = artifactErrorMsg
					}
					res.ProviderActionDetails.RunID = providerDetailsForBatch.RunID
					res.ProviderActionDetails.WorkflowPath = providerDetailsForBatch.WorkflowPath
					res.ProviderActionDetails.ArtifactName = providerDetailsForBatch.ArtifactName
				}
			}
			continue
		}

		log.Printf("[GitHub DEBUG] Batch tag %s - Parsed artifact results. Found %d results in map. Keys: %v", runIDTag, len(providerActionResults), util.GetMapKeys(providerActionResults))

		// 4. Process results for each URL from the current batch
		for _, rawURL := range currentBatchURLs {
			result := resultsMap[rawURL]

			log.Printf("[GitHub DEBUG] URL: %s (Batch Tag: %s) - Before provider update: Error='%s', ProviderRunID=%d, ProviderStatus=%d, ProviderError='%s'", rawURL, runIDTag, result.Error, result.ProviderActionDetails.RunID, result.ProviderRequest.StatusCode, result.ProviderRequest.Error)

			result.ProviderActionDetails.RunID = providerDetailsForBatch.RunID
			result.ProviderActionDetails.ArtifactName = providerDetailsForBatch.ArtifactName
			result.ProviderActionDetails.WorkflowPath = providerDetailsForBatch.WorkflowPath

			if actionResult, ok := providerActionResults[rawURL]; ok {
				result.ProviderRequest.URL = actionResult.URL
				result.ProviderRequest.StatusCode = actionResult.StatusCode
				result.ProviderRequest.BodySHA256 = actionResult.BodySHA256
				result.ProviderRequest.Body = actionResult.Body
				result.ProviderRequest.ResponseTime = time.Duration(actionResult.ResponseTimeMs).Milliseconds()
				result.ProviderRequest.Error = actionResult.Error

				result.ProviderRequest.Headers = make(http.Header)
				result.ProviderRequest.Headers = actionResult.Headers

				result.ProviderRequest.SSLCertificatePEM = actionResult.SSLCertificatePEM
				result.ProviderRequest.SSLCertificateError = actionResult.SSLCertificateError

				comparison, bypass, reason := util.CompareHTTPResponses(result.DirectRequest, result.ProviderRequest)
				result.Comparison = comparison
				result.PotentialBypass = bypass
				result.BypassReason = reason

				log.Printf("[GitHub DEBUG] URL: %s (Batch Tag: %s) - After provider update: Error='%s', ProviderRunID=%d, ProviderStatus=%d, ProviderBodySHA='%s', ProviderError='%s', Bypass=%t, BypassReason='%s'", rawURL, runIDTag, result.Error, result.ProviderActionDetails.RunID, result.ProviderRequest.StatusCode, result.ProviderRequest.BodySHA256, result.ProviderRequest.Error, result.PotentialBypass, result.BypassReason)

				if result.PotentialBypass {
					log.Printf("[GitHub] Potential Bypass for %s (tag %s): %s", rawURL, runIDTag, result.BypassReason)
				} else if result.DirectRequest.Error == "" && result.ProviderRequest.Error == "" {
					log.Printf("[GitHub] No significant differences for %s (tag %s).", rawURL, runIDTag)
				} else {
					log.Printf("[GitHub] Bypass assessment for %s (tag %s) inconclusive due to errors.", rawURL, runIDTag)
				}
			} else {
				errMsg := fmt.Sprintf("Provider result not found in artifact for URL: %s (batch tag %s)", rawURL, runIDTag)
				log.Printf("[GitHub DEBUG] URL: %s (Batch Tag: %s) - Provider result not found in artifact. Final Error='%s'", rawURL, runIDTag, result.Error)
				if result.Error == "" {
					result.Error = errMsg
				}
			}
		}
		// Optional: Add a small delay between batches if concerned about API rate limits for dispatches.
		// time.Sleep(2 * time.Second)
	}

	log.Printf("[GitHub DEBUG] Completed processing all batches. Total URLCheckResult objects: %d", len(allResults))
	for i, r := range allResults {
		log.Printf("[GitHub DEBUG] Final Result #%d for URL: %s - OverallError: '%s', DirectStatus: %d, ProviderStatus: %d, ProviderRunID: %d, ProviderError: '%s', PotentialBypass: %t, BypassReason: '%s'",
			i+1, r.URL, r.Error, r.DirectRequest.StatusCode, r.ProviderRequest.StatusCode, r.ProviderActionDetails.RunID, r.ProviderRequest.Error, r.PotentialBypass, r.BypassReason)
	}

	return allResults, nil
}

// pollForWorkflowRun waits for a workflow run triggered with a specific input to complete.
// It identifies the correct run by looking for runIDTag in the workflow run's display name.
func (p *Provider) pollForWorkflowRun(ctx context.Context, runIDTag string) (*github.WorkflowRun, error) {
	startTime := time.Now()
	pollInterval := 5 * time.Second
	maxWaitTime := 10 * time.Minute

	if p.WorkflowID == 0 {
		return nil, fmt.Errorf("WorkflowID is not set in Provider struct. Cannot poll for runs")
	}

	log.Printf("[GitHub Polling] Starting to poll for workflow runs for Workflow ID %d, expecting tag '%s' in run name", p.WorkflowID, runIDTag)

	for time.Since(startTime) < maxWaitTime {
		listOpts := &github.ListWorkflowRunsOptions{
			Event:       "workflow_dispatch",
			ListOptions: github.ListOptions{PerPage: 15},
		}

		workflowRuns, _, err := p.client.Actions.ListWorkflowRunsByID(ctx, p.Owner, p.Repo, p.WorkflowID, listOpts)
		if err != nil {
			log.Printf("[GitHub Polling] Error listing workflow runs for Workflow ID %d: %v. Retrying in %s...", p.WorkflowID, err, pollInterval)
			time.Sleep(pollInterval)
			continue
		}

		if workflowRuns == nil || len(workflowRuns.WorkflowRuns) == 0 {
			log.Printf("[GitHub Polling] No workflow runs found yet for Workflow ID %d with specified filters. Waiting %s...", p.WorkflowID, pollInterval)
			time.Sleep(pollInterval)
			continue
		}

		for _, run := range workflowRuns.WorkflowRuns {
			if strings.Contains(run.GetName(), runIDTag) {
				status := run.GetStatus()
				conclusion := run.GetConclusion()

				log.Printf("[GitHub Polling] Found candidate run ID %d with name '%s' (matching tag '%s'). Status: %s, Conclusion: %s",
					run.GetID(), run.GetName(), runIDTag, status, conclusion)

				if status == "completed" {
					log.Printf("[GitHub Polling] Tagged run ID %d was already completed. Conclusion: '%s'. Returning it directly.", run.GetID(), conclusion)
					return run, nil
				} else if status == "queued" || status == "in_progress" || status == "waiting" {
					log.Printf("[GitHub Polling] Tagged run ID %d is active (status: %s). Will monitor this one.", run.GetID(), status)
					return p.monitorSpecificRun(ctx, run.GetID())
				} else {
					log.Printf("[GitHub Polling] Tagged run ID %d found in unexpected terminal state '%s', conclusion '%s'. Returning it.", run.GetID(), status, conclusion)
					return run, nil
				}
			}
		}

		log.Printf("[GitHub Polling] No run found with tag '%s' in its name yet among the latest %d runs for Workflow ID %d. Waiting %s...", runIDTag, len(workflowRuns.WorkflowRuns), p.WorkflowID, pollInterval)
		time.Sleep(pollInterval)
	}

	return nil, fmt.Errorf("timed out after %s waiting for workflow run with tag '%s' in its name to appear for Workflow ID %d", maxWaitTime, runIDTag, p.WorkflowID)
}

// monitorSpecificRun polls a specific run ID until it completes.
func (p *Provider) monitorSpecificRun(ctx context.Context, runID int64) (*github.WorkflowRun, error) {
	pollInterval := 20 * time.Second
	maxWaitTime := 10 * time.Minute
	startTime := time.Now()

	log.Printf("[GitHub Polling] Monitoring specific workflow run ID: %d", runID)
	for time.Since(startTime) < maxWaitTime {
		run, _, err := p.client.Actions.GetWorkflowRunByID(ctx, p.Owner, p.Repo, runID)
		if err != nil {
			log.Printf("[GitHub Polling] Error getting workflow run %d: %v. Retrying...", runID, err)
			time.Sleep(pollInterval)
			continue
		}

		status := run.GetStatus()
		log.Printf("[GitHub Polling] Workflow run %d status: %s, conclusion: %s", runID, status, run.GetConclusion())

		if status == "completed" {
			return run, nil
		} else if status == "queued" || status == "in_progress" || status == "waiting" {
			time.Sleep(pollInterval)
		} else {
			return run, fmt.Errorf("workflow run %d finished with unexpected status: %s, conclusion: %s. HTML URL: %s", runID, status, run.GetConclusion(), run.GetHTMLURL())
		}
		time.Sleep(pollInterval)
	}
	return nil, fmt.Errorf("timed out after %s waiting for workflow run %d to complete", maxWaitTime, runID)
}

// downloadAndParseArtifact downloads, unzips, and parses the artifact files.
// This function is now modified to downloadAndParseArtifactsBatch and handle an array of results.
func (p *Provider) downloadAndParseArtifactsBatch(ctx context.Context, runID int64, expectedArtifactName string) (map[string]util.ProxiedResult, error) {
	actionResultsMap := make(map[string]util.ProxiedResult)

	artifacts, _, err := p.client.Actions.ListWorkflowRunArtifacts(ctx, p.Owner, p.Repo, runID, &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing artifacts for run %d: %w", runID, err)
	}

	var artifactID int64 = -1
	var foundArtifactName string
	for _, art := range artifacts.Artifacts {
		if art.GetName() == expectedArtifactName {
			artifactID = art.GetID()
			foundArtifactName = art.GetName()
			log.Printf("[GitHub Artifacts] Found artifact '%s' with ID %d", expectedArtifactName, artifactID)
			break
		}
	}

	if artifactID == -1 {
		var availableArtifactNames []string
		for _, art := range artifacts.Artifacts {
			availableArtifactNames = append(availableArtifactNames, art.GetName())
		}
		return nil, fmt.Errorf("artifact named '%s' not found for run %d. Found %d artifacts: %v", expectedArtifactName, runID, len(artifacts.Artifacts), availableArtifactNames)
	}

	downloadURL, _, err := p.client.Actions.DownloadArtifact(ctx, p.Owner, p.Repo, artifactID, 3)
	if err != nil {
		return nil, fmt.Errorf("getting download URL for artifact ID %d ('%s'): %w", artifactID, foundArtifactName, err)
	}
	if downloadURL == nil {
		return nil, fmt.Errorf("received nil download URL for artifact ID %d ('%s')", artifactID, foundArtifactName)
	}

	log.Printf("[GitHub Artifacts] Downloading artifact '%s' from %s", foundArtifactName, downloadURL.String())
	req, _ := http.NewRequestWithContext(ctx, "GET", downloadURL.String(), nil)
	httpClient := &http.Client{Timeout: 2 * time.Minute}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading artifact ID %d from %s: %w", artifactID, downloadURL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to download artifact ID %d ('%s'), status %d: %s", artifactID, foundArtifactName, resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading artifact zip body for ID %d ('%s'): %w", artifactID, foundArtifactName, err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("opening zip artifact for ID %d ('%s'): %w", artifactID, foundArtifactName, err)
	}

	var resultJSONContent []byte
	foundJSON := false
	for _, f := range zipReader.File {
		if f.Name == "result.json" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening result.json in zip ('%s'): %w", foundArtifactName, err)
			}
			resultJSONContent, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("reading result.json in zip ('%s'): %w", foundArtifactName, err)
			}
			foundJSON = true
			log.Printf("[GitHub Artifacts] Read result.json (%d bytes) from artifact zip '%s'", len(resultJSONContent), foundArtifactName)
			break
		}
	}

	if !foundJSON {
		return nil, fmt.Errorf("result.json not found in artifact %s for run %d", expectedArtifactName, runID)
	}

	var scriptResults []util.ProxiedResult
	if err := json.Unmarshal(resultJSONContent, &scriptResults); err != nil {
		var singleScriptResult util.ProxiedResult
		if errSingle := json.Unmarshal(resultJSONContent, &singleScriptResult); errSingle == nil {
			log.Printf("[GitHub Artifacts] WARNING: Expected JSON array in result.json, but got a single object. Processing as single result. Content: %s", util.TruncateString(string(resultJSONContent), 500))
			scriptResults = append(scriptResults, singleScriptResult)
		} else {
			return nil, fmt.Errorf("unmarshaling result.json into []util.ActionsResult: %w. Content snippet: %s", err, util.TruncateString(string(resultJSONContent), 200))
		}
	}

	for _, sr := range scriptResults {
		if sr.URL == "" {
			log.Printf("[GitHub Artifacts] Warning: Found a script result with an empty URL in artifact '%s'. Skipping this entry.", foundArtifactName)
			continue
		}
		actionResultsMap[sr.URL] = sr
		if sr.Error != "" {
			log.Printf("[GitHub Artifacts] Script reported error for URL %s (in batch artifact '%s'): %s", sr.URL, foundArtifactName, sr.Error)
		} else {
			log.Printf("[GitHub Artifacts] Successfully parsed result for URL %s from batch artifact '%s'. Status: %d", sr.URL, foundArtifactName, sr.StatusCode)
		}
	}

	return actionResultsMap, nil
}

// You might need to add helper functions from your util package or define them here if they don't exist yet:
// - util.ParseURL(rawURL string) (*url.URL, error)
// - util.MakeHTTPRequest(ctx context.Context, method, url string, isProxied bool) RequestDetails
// - util.SanitizeFilename(name string) string
// - util.ParseHeaders(headerString string) (http.Header, error)
// Add util.TruncateString if it doesn't exist
/*
// util.TruncateString truncates a string to a max length and adds "..."
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	if maxLength < 3 {
		return s[:maxLength] // Not enough space for "..."
	}
	return s[:maxLength-3] + "..."
}
*/
