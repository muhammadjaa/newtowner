package bitbucket

import (
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
)

const (
	bitbucketAPIBaseURL           = "https://api.bitbucket.org/2.0"
	bitbucketPipelineURLBatchSize = 20
	pollInterval                  = 10 * time.Second
	maxWaitTime                   = 15 * time.Minute
)

// BitbucketErrorDetail holds the specific error message and detail.
type BitbucketErrorDetail struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// BitbucketErrorResponse is the standard error format from Bitbucket API.
type BitbucketErrorResponse struct {
	Type  string               `json:"type"`
	Error BitbucketErrorDetail `json:"error"`
}

func (e BitbucketErrorResponse) String() string {
	if e.Error.Detail != "" {
		return fmt.Sprintf("%s: %s", e.Error.Message, e.Error.Detail)
	}
	return e.Error.Message
}

// BitbucketTriggerPipelineRequest represents the request body for triggering a pipeline
type BitbucketTriggerPipelineRequest struct {
	Target struct {
		RefType  string `json:"ref_type"`
		Type     string `json:"type"`
		RefName  string `json:"ref_name"`
		Selector struct {
			Type    string `json:"type"`
			Pattern string `json:"pattern"`
		} `json:"selector"`
	} `json:"target"`
	Variables []struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Secured bool   `json:"secured"`
	} `json:"variables"`
}

// BitbucketPipeline represents a Bitbucket pipeline
type BitbucketPipeline struct {
	UUID        string                  `json:"uuid"`
	State       *BitbucketPipelineState `json:"state"`
	BuildNumber int                     `json:"build_number"`
	Links       struct {
		Self struct {
			Href string `json:"href"`
		} `json:"self"`
		Steps struct {
			Href string `json:"href"`
		} `json:"steps"`
	} `json:"links"`
}

type BitbucketPipelineState struct {
	Name   string                   `json:"name"`
	Type   string                   `json:"type"`
	Result *BitbucketPipelineResult `json:"result,omitempty"`
}

type BitbucketPipelineResult struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type URLCheckResult struct {
	URL             string
	Error           string
	DirectRequest   util.RequestDetails
	ProviderRequest util.RequestDetails
	Comparison      util.ComparisonResult
	PotentialBypass bool
	BypassReason    string

	ProviderPipelineDetails struct {
		PipelineUUID   string
		PipelineNumber int
		StepUUID       string
		StepName       string
		PipelineURL    string
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
	return "Bitbucket Pipeline Request"
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.ProviderPipelineDetails.PipelineUUID == "" {
		return "Pipeline UUID: N/A (trigger or monitoring failed)"
	}
	return fmt.Sprintf("Pipeline UUID: %s, Step UUID: %s (%s)",
		r.ProviderPipelineDetails.PipelineUUID,
		r.ProviderPipelineDetails.StepUUID,
		r.ProviderPipelineDetails.StepName)
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

type BitbucketProvider struct {
	client             *http.Client
	Workspace          string
	RepoSlug           string
	PipelineRef        string
	ArtifactStepName   string
	AccessToken        string
	CustomPipelineName string
}

// NewBitbucketProvider creates and initializes a new Bitbucket Provider.
func NewBitbucketProvider(ctx context.Context, workspace, repoSlug, pipelineRef, accessToken, pipelineSelectorPattern string) (*BitbucketProvider, error) {
	if workspace == "" {
		return nil, fmt.Errorf("bitbucket workspace is required")
	}
	if repoSlug == "" {
		return nil, fmt.Errorf("bitbucket repository slug is required")
	}
	if accessToken == "" {
		return nil, fmt.Errorf("bitbucket access token is required for authentication")
	}
	if pipelineRef == "" {
		pipelineRef = "main"
		log.Printf("Pipeline reference for Bitbucket pipeline not specified, using default: %s", pipelineRef)
	}
	// the pipelineselectorpattern is typically passed from main.go (e.g., "newtowner-http-check")
	// and is used for triggering the pipeline via its selector pattern.
	if pipelineSelectorPattern == "" {
		return nil, fmt.Errorf("bitbucket pipeline selector pattern is required")
	}

	// this is the actual name of the step in bitbucket-pipelines.yml that produces the artifact.
	const ymlArtifactStepName = "Newtowner HTTP Check"

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	provider := &BitbucketProvider{
		client:             client,
		Workspace:          workspace,
		RepoSlug:           repoSlug,
		PipelineRef:        pipelineRef,
		ArtifactStepName:   ymlArtifactStepName, // Use the correct YML step name for finding artifacts
		AccessToken:        accessToken,
		CustomPipelineName: pipelineSelectorPattern, // Use the pattern from main.go for triggering pipelines
	}

	log.Printf("[Bitbucket Provider] Verifying repository access for %s/%s...", workspace, repoSlug)
	repoURL := fmt.Sprintf("%s/repositories/%s/%s", bitbucketAPIBaseURL, workspace, repoSlug)
	req, err := http.NewRequestWithContext(ctx, "GET", repoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository verification request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	log.Printf("[Bitbucket API DEBUG] Request: GET %s", repoURL)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify repository access: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Bitbucket API DEBUG] Response Status: GET %s -> %d", repoURL, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Bitbucket API DEBUG] Response Body: %s", string(body))
		return nil, fmt.Errorf("failed to verify repository access: status %d", resp.StatusCode)
	}

	var repoInfo struct {
		UUID  string `json:"uuid"`
		Links struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
		return nil, fmt.Errorf("failed to parse repository info: %w", err)
	}

	log.Printf("[Bitbucket Provider] Successfully accessed repository: %s/%s (UUID: %s). Link: %s",
		workspace, repoSlug, repoInfo.UUID, repoInfo.Links.HTML.Href)

	log.Printf("[Bitbucket Provider] Verifying pipeline access...")
	pipelinesURL := fmt.Sprintf("%s/repositories/%s/%s/pipelines/", bitbucketAPIBaseURL, workspace, repoSlug)
	req, err = http.NewRequestWithContext(ctx, "GET", pipelinesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline verification request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	log.Printf("[Bitbucket API DEBUG] Request: GET %s", pipelinesURL)
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify pipeline access: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Bitbucket API DEBUG] Response Status: GET %s -> %d", pipelinesURL, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Bitbucket API DEBUG] Response Body: %s", string(body))
		return nil, fmt.Errorf("failed to verify pipeline access: status %d", resp.StatusCode)
	}

	var pipelinesInfo struct {
		Values []struct {
			BuildNumber int `json:"build_number"`
			State       struct {
				Name string `json:"name"`
			} `json:"state"`
		} `json:"values"`
		Size int `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pipelinesInfo); err != nil {
		return nil, fmt.Errorf("failed to parse pipeline info: %w", err)
	}

	log.Printf("[Bitbucket Provider] Successfully accessed pipelines. Found %d pipelines in total.", pipelinesInfo.Size)
	if len(pipelinesInfo.Values) > 0 {
		latest := pipelinesInfo.Values[0]
		log.Printf("[Bitbucket Provider] Latest pipeline: #%d, State: %s", latest.BuildNumber, latest.State.Name)
	}

	log.Printf("Bitbucket Provider initialized for Workspace: %s, Repo: %s, Pipeline Ref: %s, Selector: %s, Artifact Step: %s",
		workspace, repoSlug, pipelineRef, provider.CustomPipelineName, provider.ArtifactStepName)

	return provider, nil
}

// CheckURLs performs checks for the given URLs using Bitbucket Pipelines.
func (p *BitbucketProvider) CheckURLs(urls []string) ([]URLCheckResult, error) {
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
			log.Printf("[Bitbucket DEBUG] URL: %s - Initial population: Error parsing URL: %v", rawURL, err)
			continue
		}
		result.TargetHostname = parsedURL.Hostname()

		log.Printf("[Bitbucket] Making direct request to %s", rawURL)
		result.DirectRequest = util.MakeHTTPRequest(ctx, "GET", rawURL, false)
		if result.DirectRequest.Error != "" {
			log.Printf("[Bitbucket] Direct request error for %s: %s", rawURL, result.DirectRequest.Error)
		}

		if result.TargetHostname != "" {
			geoLoc, resolvedIP, geoErr := util.ResolveHostAndGetGeoLocation(result.TargetHostname)
			if geoErr == nil {
				result.TargetResolvedIP = resolvedIP.String()
				result.TargetGeoCountry = geoLoc.CountryCode
				result.TargetGeoRegion = geoLoc.RegionName
			} else {
				log.Printf("[Bitbucket] Warning: Could not get GeoIP for %s: %v", result.TargetHostname, geoErr)
			}
		}
	}

	var validURLsForPipeline []string
	for _, r := range allResults {
		if r.Error == "" && r.TargetHostname != "" {
			validURLsForPipeline = append(validURLsForPipeline, r.URL)
		}
	}

	if len(validURLsForPipeline) == 0 {
		log.Printf("[Bitbucket] No valid URLs with successfully parsed hostnames to process via pipeline.")
		return allResults, nil
	}

	for i := 0; i < len(validURLsForPipeline); i += bitbucketPipelineURLBatchSize {
		end := min(i+bitbucketPipelineURLBatchSize, len(validURLsForPipeline))
		currentBatchURLs := validURLsForPipeline[i:end]

		log.Printf("[Bitbucket] Processing batch %d, URLs: %d. Batch: %v", (i/bitbucketPipelineURLBatchSize)+1, len(currentBatchURLs), currentBatchURLs)

		batchTargetURLString := strings.Join(currentBatchURLs, ",")
		runIDTag := fmt.Sprintf("newtowner-bb-%s-%s-%d", util.SanitizeFilename(p.Workspace), util.SanitizeFilename(p.RepoSlug), time.Now().UnixNano())

		// trigger pipeline
		triggeredPipelineUUID, triggeredPipelineWebURL, triggerErr := p.triggerBitbucketPipeline(ctx, batchTargetURLString, runIDTag)
		if triggerErr != nil {
			dispatchErrorMsg := fmt.Sprintf("Failed to trigger Bitbucket pipeline (tag %s): %v", runIDTag, triggerErr)
			log.Printf("[Bitbucket ERROR] %s", dispatchErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok && res.Error == "" {
					res.Error = dispatchErrorMsg
				}
			}
			continue
		}

		log.Printf("[Bitbucket] Pipeline triggered. UUID: %s, URL: %s", triggeredPipelineUUID, triggeredPipelineWebURL)
		for _, rawURL := range currentBatchURLs {
			if res, ok := resultsMap[rawURL]; ok {
				res.ProviderPipelineDetails.PipelineUUID = triggeredPipelineUUID
				res.ProviderPipelineDetails.PipelineURL = triggeredPipelineWebURL
				res.ProviderPipelineDetails.StepName = p.ArtifactStepName
			}
		}

		// wait for completion
		completedPipeline, pollErr := p.pollForPipelineCompletion(ctx, triggeredPipelineUUID)
		if pollErr != nil {
			pollErrorMsg := fmt.Sprintf("Error waiting for Bitbucket pipeline %s (tag %s) to complete: %v", triggeredPipelineUUID, runIDTag, pollErr)
			log.Printf("[Bitbucket ERROR] %s", pollErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = pollErrorMsg
					}
					res.ProviderRequest.Error = pollErrorMsg
					if completedPipeline != nil {
						res.ProviderPipelineDetails.PipelineNumber = completedPipeline.BuildNumber
					}
				}
			}
			continue
		}

		log.Printf("[Bitbucket] Pipeline %s (Build #%d, tag %s) completed with state: %s, result: %s",
			completedPipeline.UUID, completedPipeline.BuildNumber, runIDTag, completedPipeline.State.Name, completedPipeline.State.Result.Name)

		for _, rawURL := range currentBatchURLs {
			if res, ok := resultsMap[rawURL]; ok {
				res.ProviderPipelineDetails.PipelineNumber = completedPipeline.BuildNumber
			}
		}

		if completedPipeline.State.Name != "COMPLETED" || completedPipeline.State.Result.Name != "SUCCESSFUL" {
			pipelineStatusErrorMsg := fmt.Sprintf("Bitbucket pipeline %s (Build #%d, tag %s) did not succeed. State: %s, Result: %s. URL: %s",
				completedPipeline.UUID, completedPipeline.BuildNumber, runIDTag, completedPipeline.State.Name, completedPipeline.State.Result.Name, triggeredPipelineWebURL)
			log.Printf("[Bitbucket ERROR] %s", pipelineStatusErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = pipelineStatusErrorMsg
					}
					res.ProviderRequest.Error = pipelineStatusErrorMsg
				}
			}
			continue
		}

		// download and parse artifacts
		actionResultsMap, downloadedArtifactStepUUID, artifactErr := p.downloadAndParseArtifactsBatch(ctx, completedPipeline.UUID, p.ArtifactStepName, runIDTag)
		if artifactErr != nil {
			artifactErrorMsg := fmt.Sprintf("Failed to download/parse artifact for pipeline %s, step '%s' (tag %s): %v", completedPipeline.UUID, p.ArtifactStepName, runIDTag, artifactErr)
			log.Printf("[Bitbucket ERROR] %s", artifactErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = artifactErrorMsg
					}
					res.ProviderRequest.Error = artifactErrorMsg
					if downloadedArtifactStepUUID != "" {
						res.ProviderPipelineDetails.StepUUID = downloadedArtifactStepUUID
					}
				}
			}
			continue
		}

		log.Printf("[Bitbucket DEBUG] Batch tag %s - Parsed artifact results from step %s. Found %d results in map.", runIDTag, downloadedArtifactStepUUID, len(actionResultsMap))

		for _, rawURL := range currentBatchURLs {
			result := resultsMap[rawURL]
			result.ProviderPipelineDetails.StepUUID = downloadedArtifactStepUUID

			if actionResult, ok := actionResultsMap[rawURL]; ok {
				result.ProviderRequest.URL = actionResult.URL
				result.ProviderRequest.StatusCode = actionResult.StatusCode
				result.ProviderRequest.BodySHA256 = actionResult.BodySHA256
				result.ProviderRequest.Body = actionResult.Body
				result.ProviderRequest.ResponseTime = time.Duration(actionResult.ResponseTimeMs).Milliseconds()
				result.ProviderRequest.Error = actionResult.Error

				result.ProviderRequest.Headers = make(http.Header)
				for k, values := range actionResult.Headers {
					for _, v := range values {
						result.ProviderRequest.Headers.Add(k, v)
					}
				}

				result.ProviderRequest.SSLCertificatePEM = actionResult.SSLCertificatePEM
				result.ProviderRequest.SSLCertificateError = actionResult.SSLCertificateError

				if result.ProviderRequest.Error == "" && result.DirectRequest.Error == "" {
					comparison, bypass, reason := util.CompareHTTPResponses(result.DirectRequest, result.ProviderRequest)
					result.Comparison = comparison
					result.PotentialBypass = bypass
					result.BypassReason = reason
				} else if result.ProviderRequest.Error != "" {
					log.Printf("[Bitbucket] Skipping comparison for %s due to provider script error: %s", rawURL, result.ProviderRequest.Error)
				} else {
					log.Printf("[Bitbucket] Skipping comparison for %s due to direct request error: %s", rawURL, result.DirectRequest.Error)
				}

				if result.Error == "" && result.ProviderRequest.Error != "" {
					result.Error = fmt.Sprintf("Provider script error for %s: %s", rawURL, result.ProviderRequest.Error)
				}
			} else {
				providerNoResultMsg := fmt.Sprintf("Provider result not found in artifact for URL: %s (pipeline %s, step %s, tag %s)", rawURL, completedPipeline.UUID, downloadedArtifactStepUUID, runIDTag)
				log.Printf("[Bitbucket WARN] %s", providerNoResultMsg)
				if result.Error == "" {
					result.Error = providerNoResultMsg
				}
				result.ProviderRequest.Error = providerNoResultMsg
			}
		}
	}

	log.Printf("[Bitbucket DEBUG] Completed processing all batches. Total results: %d", len(allResults))
	return allResults, nil
}

// triggerBitbucketPipeline triggers a new pipeline run.
func (p *BitbucketProvider) triggerBitbucketPipeline(ctx context.Context, targetURLs, runIDTag string) (pipelineUUID string, pipelineWebURL string, err error) {
	log.Printf("[Bitbucket] Triggering pipeline for repo %s/%s, ref %s, URLs: %s, Tag: %s", p.Workspace, p.RepoSlug, p.PipelineRef, targetURLs, runIDTag)

	triggerURL := fmt.Sprintf("%s/repositories/%s/%s/pipelines/", bitbucketAPIBaseURL, p.Workspace, p.RepoSlug)

	reqBody := BitbucketTriggerPipelineRequest{}
	reqBody.Target.RefType = "branch"
	reqBody.Target.Type = "pipeline_ref_target"
	reqBody.Target.RefName = p.PipelineRef
	reqBody.Target.Selector.Type = "custom"
	reqBody.Target.Selector.Pattern = p.CustomPipelineName

	reqBody.Variables = []struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Secured bool   `json:"secured"`
	}{
		{Key: "TARGET_URLS", Value: targetURLs, Secured: false},
		{Key: "RUN_ID_TAG", Value: runIDTag, Secured: false},
		{Key: "REPO_ACCESS_TOKEN", Value: p.AccessToken, Secured: true},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal pipeline trigger request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", triggerURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", fmt.Errorf("failed to create pipeline trigger request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	log.Printf("[Bitbucket] Using custom pipeline selector: %s", p.CustomPipelineName)
	log.Printf("[Bitbucket API DEBUG] Request: POST %s", triggerURL)
	log.Printf("[Bitbucket API DEBUG] Request Body: (type bitbucket.BitbucketTriggerPipelineRequest, not directly logged as JSON string)")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to trigger pipeline: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Bitbucket API DEBUG] Response Status: POST %s -> %d", triggerURL, resp.StatusCode)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Bitbucket API DEBUG] Response Body: %s", string(body))
		return "", "", fmt.Errorf("failed to trigger pipeline: status %d", resp.StatusCode)
	}

	var pipelineResp struct {
		UUID  string `json:"uuid"`
		Links struct {
			Self struct {
				Href string `json:"href"`
			} `json:"self"`
		} `json:"links"`
		BuildNumber int `json:"build_number"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pipelineResp); err != nil {
		return "", "", fmt.Errorf("failed to parse pipeline response: %w", err)
	}

	pipelineWebURL = fmt.Sprintf("https://bitbucket.org/%s/%s/addon/pipelines/home#!/results/%d",
		p.Workspace, p.RepoSlug, pipelineResp.BuildNumber)

	log.Printf("[Bitbucket] Triggered pipeline UUID: %s, Build: #%d. WebURL: %s",
		pipelineResp.UUID, pipelineResp.BuildNumber, pipelineWebURL)

	return pipelineResp.UUID, pipelineWebURL, nil
}

// pollForPipelineCompletion waits for a Bitbucket pipeline to complete.
func (p *BitbucketProvider) pollForPipelineCompletion(ctx context.Context, pipelineUUID string) (*BitbucketPipeline, error) {
	log.Printf("[Bitbucket Polling] Waiting for pipeline %s in repo %s/%s to complete...", pipelineUUID, p.Workspace, p.RepoSlug)

	startTime := time.Now()
	for {
		if time.Since(startTime) > maxWaitTime {
			return nil, fmt.Errorf("timed out waiting for pipeline completion after %v", maxWaitTime)
		}

		pipelineURL := fmt.Sprintf("%s/repositories/%s/%s/pipelines/%s", bitbucketAPIBaseURL, p.Workspace, p.RepoSlug, pipelineUUID)
		req, err := http.NewRequestWithContext(ctx, "GET", pipelineURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create pipeline status request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+p.AccessToken)

		log.Printf("[Bitbucket API DEBUG] Request: GET %s", pipelineURL)
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to get pipeline status: %w", err)
		}

		log.Printf("[Bitbucket API DEBUG] Response Status: GET %s -> %d", pipelineURL, resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[Bitbucket API DEBUG] Response Body: %s", string(body))
			return nil, fmt.Errorf("failed to get pipeline status: status %d", resp.StatusCode)
		}

		var pipeline BitbucketPipeline
		if err := json.NewDecoder(resp.Body).Decode(&pipeline); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to parse pipeline status: %w", err)
		}
		resp.Body.Close()

		pipelineWebURL := fmt.Sprintf("https://bitbucket.org/%s/%s/addon/pipelines/home#!/results/%d",
			p.Workspace, p.RepoSlug, pipeline.BuildNumber)

		log.Printf("[Bitbucket Polling] Pipeline %s (Build #%d) status: %s. URL: %s",
			pipeline.UUID, pipeline.BuildNumber, pipeline.State.Name, pipelineWebURL)

		switch pipeline.State.Name {
		case "COMPLETED":
			log.Printf("[Bitbucket Polling] Pipeline %s completed. Result: %s", pipeline.UUID, pipeline.State.Result.Name)
			return &pipeline, nil
		case "FAILED", "STOPPED", "ERROR":
			return &pipeline, fmt.Errorf("pipeline failed with state: %s", pipeline.State.Name)
		case "PARSING", "PENDING", "IN_PROGRESS":
			log.Printf("[Bitbucket Polling] Pipeline %s is still in progress (status: %s). Waiting %s...",
				pipeline.UUID, pipeline.State.Name, pollInterval)
			time.Sleep(pollInterval)
			continue
		default:
			log.Printf("[Bitbucket Polling] Pipeline %s has unknown or unexpected state: '%s'. Continuing to poll.",
				pipeline.UUID, pipeline.State.Name)
			time.Sleep(pollInterval)
			continue
		}
	}
}

// downloadAndParseArtifactsBatch downloads and parses the result.json artifact from a specific step in a pipeline.
func (p *BitbucketProvider) downloadAndParseArtifactsBatch(ctx context.Context, pipelineUUID string, artifactStepName string, runIDTag string) (map[string]util.ProxiedResult, string, error) {
	const ymlArtifactStepNameForLookup = "Newtowner HTTP Check"

	log.Printf("[Bitbucket Artifacts] Looking for step '%s' (using hardcoded lookup: '%s') in pipeline %s to download artifacts.", artifactStepName, ymlArtifactStepNameForLookup, pipelineUUID)

	stepsURL := fmt.Sprintf("%s/repositories/%s/%s/pipelines/%s/steps", bitbucketAPIBaseURL, p.Workspace, p.RepoSlug, pipelineUUID)
	req, err := http.NewRequestWithContext(ctx, "GET", stepsURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create steps request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get pipeline steps: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("failed to get pipeline steps: status %d, body: %s", resp.StatusCode, string(body))
	}

	var stepsResp struct {
		Values []struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
		} `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stepsResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse pipeline steps: %w", err)
	}

	log.Printf("[Bitbucket Artifacts] Available steps in pipeline:")
	for _, step := range stepsResp.Values {
		log.Printf("[Bitbucket Artifacts] - Step: %s (UUID: %s)", step.Name, step.UUID)
	}

	var targetStepUUID string
	for _, step := range stepsResp.Values {
		if step.Name == ymlArtifactStepNameForLookup { // Use hardcoded name for lookup
			targetStepUUID = step.UUID
			break
		}
	}

	if targetStepUUID == "" {
		availableSteps := make([]string, len(stepsResp.Values))
		for i, step := range stepsResp.Values {
			availableSteps[i] = step.Name
		}
		return nil, "", fmt.Errorf("step '%s' not found in pipeline. Available steps: %v", ymlArtifactStepNameForLookup, availableSteps)
	}

	// get artifacts for the step
	log.Printf("[Bitbucket Artifacts] Found step '%s' with UUID: %s. Now listing its artifacts.", ymlArtifactStepNameForLookup, targetStepUUID)

	// get the list of downloads
	downloadsURL := fmt.Sprintf("%s/repositories/%s/%s/downloads",
		bitbucketAPIBaseURL, p.Workspace, p.RepoSlug)
	req, err = http.NewRequestWithContext(ctx, "GET", downloadsURL, nil)
	if err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to create downloads request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("Accept", "application/json")

	log.Printf("[Bitbucket API DEBUG] Request: GET %s", downloadsURL)
	resp, err = p.client.Do(req)
	if err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to get downloads: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Bitbucket API DEBUG] Response Status: GET %s -> %d", downloadsURL, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Bitbucket API DEBUG] Response Body: %s", string(body))
		return nil, targetStepUUID, fmt.Errorf("failed to get downloads: status %d, body: %s", resp.StatusCode, string(body))
	}

	var downloadsResp struct {
		Values []struct {
			Name  string `json:"name"`
			Links struct {
				Self struct {
					Href string `json:"href"`
				} `json:"self"`
			} `json:"links"`
		} `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&downloadsResp); err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to parse downloads: %w", err)
	}

	log.Printf("[Bitbucket Artifacts] Available downloads:")
	for _, download := range downloadsResp.Values {
		log.Printf("[Bitbucket Artifacts] - Download: %s", download.Name)
	}

	// look for the result file with the run_id_tag
	expectedFilename := fmt.Sprintf("newtowner-check-result-%s.json", runIDTag)
	log.Printf("[Bitbucket Artifacts] Looking for download file: %s", expectedFilename)
	var downloadURL string
	for _, download := range downloadsResp.Values {
		log.Printf("[Bitbucket Artifacts] Checking download: %s", download.Name)
		if download.Name == expectedFilename {
			downloadURL = download.Links.Self.Href
			break
		}
	}

	if downloadURL == "" {
		availableDownloads := make([]string, len(downloadsResp.Values))
		for i, download := range downloadsResp.Values {
			availableDownloads[i] = download.Name
		}
		return nil, targetStepUUID, fmt.Errorf("result file '%s' not found in downloads. Available downloads: %v",
			expectedFilename, availableDownloads)
	}

	log.Printf("[Bitbucket Artifacts] Found download '%s'. Download URL: %s", expectedFilename, downloadURL)
	req, err = http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)

	resp, err = p.client.Do(req)
	if err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[Bitbucket API DEBUG] Response Status: GET %s -> %d", downloadURL, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Bitbucket API DEBUG] Response Body: %s", string(body))
		return nil, targetStepUUID, fmt.Errorf("failed to download file: status %d, body: %s", resp.StatusCode, string(body))
	}

	resultJSONContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to read file content: %w", err)
	}

	var results []util.ProxiedResult
	if err := json.Unmarshal(resultJSONContent, &results); err != nil {
		return nil, targetStepUUID, fmt.Errorf("failed to parse result.json: %w", err)
	}

	resultsMap := make(map[string]util.ProxiedResult)
	for _, result := range results {
		resultsMap[result.URL] = result
	}

	log.Printf("[Bitbucket Artifacts] Successfully downloaded and parsed result file '%s'", expectedFilename)
	return resultsMap, targetStepUUID, nil
}
