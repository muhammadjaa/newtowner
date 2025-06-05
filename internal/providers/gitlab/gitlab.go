package gitlab

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

	gitlab "gitlab.com/gitlab-org/api/client-go" // Official GitLab Go SDK, aliased to gitlab
)

const (
	gitlabPipelineURLBatchSize = 20 // Max URLs to process in a single pipeline run (configurable)
	pollInterval               = 10 * time.Second
	maxWaitTime                = 15 * time.Minute // Max time to wait for a pipeline to complete
)

// URLCheckResult stores the result of a check for a single URL via GitLab Pipelines.
type URLCheckResult struct {
	URL             string
	Error           string
	DirectRequest   util.RequestDetails
	ProviderRequest util.RequestDetails
	Comparison      util.ComparisonResult
	PotentialBypass bool
	BypassReason    string

	ProviderPipelineDetails struct { // Specific to GitLab provider
		PipelineID  int
		JobID       int    // ID of the job that generated the artifact
		JobName     string // Name of the job that generated the artifact (e.g., "http_check_job")
		PipelineURL string // HTML URL to the pipeline
		// ArtifactJobName is part of GitLabProvider struct, not duplicated here
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
	return "GitLab Pipeline Request"
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.ProviderPipelineDetails.PipelineID == 0 {
		return "Pipeline ID: N/A (trigger or monitoring failed)"
	}
	return fmt.Sprintf("Pipeline ID: %d, Job ID: %d (%s)", r.ProviderPipelineDetails.PipelineID, r.ProviderPipelineDetails.JobID, r.ProviderPipelineDetails.JobName)
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

// GitLabProvider implements the Newtowner provider interface for GitLab CI/CD.
// Note: ProjectID can be the numeric ID or the URL-encoded path of the project.
type GitLabProvider struct {
	client               *gitlab.Client // Corrected type
	ProjectID            string         // GitLab Project ID (e.g., "12345") or Path (e.g., "group/subgroup/project")
	PipelineRef          string         // The branch or tag to run the pipeline on (e.g., "main")
	ArtifactJobName      string         // The name of the job in .gitlab-ci.yml that produces the artifact (e.g., "http_check_job")
	PipelineTriggerToken string         // Optional: Dedicated token for triggering pipelines
}

// NewGitLabProvider creates and initializes a new GitLab Provider.
func NewGitLabProvider(ctx context.Context, pat, projectID, pipelineRef, artifactJobName string, pipelineTriggerToken string) (*GitLabProvider, error) {
	if pat == "" {
		return nil, fmt.Errorf("GitLab Personal Access Token (PAT) is required for API interactions (polling, artifacts, etc.)")
	}
	if pipelineTriggerToken == "" {
		return nil, fmt.Errorf("GitLab Pipeline Trigger Token is required for triggering pipelines")
	}
	if projectID == "" {
		return nil, fmt.Errorf("GitLab Project ID or Path is required")
	}
	if pipelineRef == "" {
		pipelineRef = "main" // Default to main if not specified
		log.Printf("Pipeline reference for GitLab pipeline not specified, using: %s", pipelineRef)
	}
	if artifactJobName == "" {
		return nil, fmt.Errorf("GitLab artifact job name is required (name of the job in .gitlab-ci.yml that produces the result artifact)")
	}

	var glClient *gitlab.Client
	var err error

	glClient, err = gitlab.NewClient(pat)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitLab client: %w", err)
	}

	// Verify client connectivity by trying to get the project (only if PAT is available for this).
	// If only a trigger token is provided, this check might not be possible or relevant in the same way.
	if pat != "" {
		_, _, projectErr := glClient.Projects.GetProject(projectID, nil, gitlab.WithContext(ctx))
		if projectErr != nil {
			return nil, fmt.Errorf("failed to access GitLab project '%s' (check Project ID/Path and PAT permissions): %w", projectID, projectErr)
		}
		log.Printf("GitLab Provider PAT authenticated and project '%s' accessible.", projectID)
	} else {
		log.Printf("GitLab Provider initialized with a Pipeline Trigger Token. Project accessibility check via PAT skipped.")
	}

	log.Printf("GitLab Provider initialized for Project: %s, Pipeline Ref: %s, Artifact Job: %s", projectID, pipelineRef, artifactJobName)
	log.Printf("Using GitLab Pipeline Trigger Token for pipeline creation.")

	return &GitLabProvider{
		client:               glClient,
		ProjectID:            projectID,
		PipelineRef:          pipelineRef,
		ArtifactJobName:      artifactJobName,
		PipelineTriggerToken: pipelineTriggerToken,
	}, nil
}

// pollForPipelineCompletion waits for a GitLab pipeline to complete.
func (p *GitLabProvider) pollForPipelineCompletion(ctx context.Context, pipelineID int) (*gitlab.Pipeline, error) {
	startTime := time.Now()
	log.Printf("[GitLab Polling] Waiting for pipeline %d in project %s to complete...", pipelineID, p.ProjectID)

	for {
		if time.Since(startTime) > maxWaitTime {
			return nil, fmt.Errorf("timed out after %s waiting for pipeline %d to complete", maxWaitTime, pipelineID)
		}

		pipe, _, err := p.client.Pipelines.GetPipeline(p.ProjectID, pipelineID, gitlab.WithContext(ctx))
		if err != nil {
			log.Printf("[GitLab Polling] Error getting pipeline %d: %v. Retrying in %s...", pipelineID, err, pollInterval)
			time.Sleep(pollInterval)
			continue
		}

		log.Printf("[GitLab Polling] Pipeline %d status: %s (SHA: %s)", pipe.ID, pipe.Status, pipe.SHA)

		switch pipe.Status {
		case "success":
			log.Printf("[GitLab Polling] Pipeline %d completed successfully.", pipe.ID)
			return pipe, nil
		case "failed", "canceled", "skipped":
			log.Printf("[GitLab Polling] Pipeline %d finished with status: %s. URL: %s", pipe.ID, pipe.Status, pipe.WebURL)
			return pipe, fmt.Errorf("pipeline %d did not succeed. Status: %s. URL: %s", pipe.ID, pipe.Status, pipe.WebURL)
		case "running", "pending", "created", "waiting_for_resource", "preparing":
			// Still in progress, continue polling
			log.Printf("[GitLab Polling] Pipeline %d is still in progress (status: %s). Waiting %s...", pipe.ID, pipe.Status, pollInterval)
		default:
			// Unknown status, treat as an issue but keep polling for a bit
			log.Printf("[GitLab Polling] Pipeline %d has unknown status: %s. Continuing to poll.", pipe.ID, pipe.Status)
		}

		time.Sleep(pollInterval)
	}
}

// downloadAndParseArtifactsBatch downloads and parses the result.json artifact from a specific job in a pipeline.
// It now returns the job ID of the job from which the artifact was downloaded.
func (p *GitLabProvider) downloadAndParseArtifactsBatch(ctx context.Context, pipelineID int, jobNameForArtifact string) (map[string]util.ProxiedResult, int, error) {
	actionResultsMap := make(map[string]util.ProxiedResult)

	log.Printf("[GitLab Artifacts] Looking for job '%s' in pipeline %d to download artifacts.", jobNameForArtifact, pipelineID)

	var targetJobID int = -1
	listPipelineJobsOpts := &gitlab.ListJobsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}

	jobs, _, err := p.client.Jobs.ListPipelineJobs(p.ProjectID, pipelineID, listPipelineJobsOpts, gitlab.WithContext(ctx))
	if err != nil {
		return nil, -1, fmt.Errorf("failed to list jobs for pipeline %d: %w", pipelineID, err)
	}

	for _, job := range jobs {
		if job.Name == jobNameForArtifact {
			if job.Status == "success" {
				targetJobID = job.ID
				log.Printf("[GitLab Artifacts] Found successful job '%s' (ID: %d) in pipeline %d.", jobNameForArtifact, targetJobID, pipelineID)
				break
			} else {
				log.Printf("[GitLab Artifacts] Found job '%s' (ID: %d) but it did not succeed (status: %s). Searching further.", jobNameForArtifact, job.ID, job.Status)
			}
		}
	}

	if targetJobID == -1 {
		var jobNames []string
		for _, job := range jobs {
			jobNames = append(jobNames, fmt.Sprintf("%s (status: %s)", job.Name, job.Status))
		}
		return nil, -1, fmt.Errorf("no successful job named '%s' found in pipeline %d. Searched jobs: %v", jobNameForArtifact, pipelineID, jobNames)
	}

	log.Printf("[GitLab Artifacts] Downloading artifacts for job ID %d (expected to contain result.json).", targetJobID)

	artifactReader, resp, err := p.client.Jobs.GetJobArtifacts(p.ProjectID, targetJobID, gitlab.WithContext(ctx))
	if err != nil {
		return nil, targetJobID, fmt.Errorf("failed to get artifact download reader for job %d: %w", targetJobID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, targetJobID, fmt.Errorf("failed to download artifact for job %d, status %d: %s", targetJobID, resp.StatusCode, string(bodyBytes))
	}

	zipData, err := io.ReadAll(artifactReader)
	if err != nil {
		return nil, targetJobID, fmt.Errorf("failed to read artifact zip data for job %d: %w", targetJobID, err)
	}

	log.Printf("[GitLab Artifacts] Downloaded %d bytes of artifact data for job %d.", len(zipData), targetJobID)

	zipBytesReader := bytes.NewReader(zipData)
	zipContentReader, err := zip.NewReader(zipBytesReader, int64(len(zipData)))
	if err != nil {
		return nil, targetJobID, fmt.Errorf("failed to open zip reader for artifact from job %d: %w", targetJobID, err)
	}

	var resultJSONContent []byte
	foundJSON := false
	for _, f := range zipContentReader.File {
		if f.Name == "result.json" {
			rc, err := f.Open()
			if err != nil {
				return nil, targetJobID, fmt.Errorf("failed to open result.json within zip from job %d: %w", targetJobID, err)
			}
			resultJSONContent, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, targetJobID, fmt.Errorf("failed to read result.json content from zip for job %d: %w", targetJobID, err)
			}
			foundJSON = true
			log.Printf("[GitLab Artifacts] Successfully read result.json (%d bytes) from job %d artifact.", len(resultJSONContent), targetJobID)
			break
		}
	}

	if !foundJSON {
		var fileNamesInZip []string
		for _, f := range zipContentReader.File {
			fileNamesInZip = append(fileNamesInZip, f.Name)
		}
		return nil, targetJobID, fmt.Errorf("result.json not found in artifact zip from job %d. Files in zip: %v", targetJobID, fileNamesInZip)
	}

	var scriptResults []util.ProxiedResult
	if err := json.Unmarshal(resultJSONContent, &scriptResults); err != nil {
		var singleScriptResult util.ProxiedResult
		if errSingle := json.Unmarshal(resultJSONContent, &singleScriptResult); errSingle == nil {
			log.Printf("[GitLab Artifacts] WARNING: Expected JSON array in result.json, but got single object. Treating as array with one item. Content: %s", util.TruncateString(string(resultJSONContent), 200))
			scriptResults = append(scriptResults, singleScriptResult)
		} else {
			return nil, targetJobID, fmt.Errorf("unmarshaling result.json from job %d: %w. Original error for array: %s. Content snippet: %s", targetJobID, errSingle, err, util.TruncateString(string(resultJSONContent), 200))
		}
	}

	for _, sr := range scriptResults {
		if sr.URL == "" {
			log.Printf("[GitLab Artifacts] Warning: Found a script result with an empty URL in artifact from job %d. Skipping entry.", targetJobID)
			continue
		}
		actionResultsMap[sr.URL] = sr
		if sr.Error != "" {
			log.Printf("[GitLab Artifacts] Script reported error for URL %s (job %d): %s", sr.URL, targetJobID, sr.Error)
		} else {
			log.Printf("[GitLab Artifacts] Successfully parsed result for URL %s from job %d artifact. Status: %d", sr.URL, targetJobID, sr.StatusCode)
		}
	}

	log.Printf("[GitLab Artifacts] Processed %d results from artifact for job %d.", len(actionResultsMap), targetJobID)
	return actionResultsMap, targetJobID, nil
}

// CheckURLs performs checks for the given URLs using GitLab Pipelines.
func (p *GitLabProvider) CheckURLs(urls []string) ([]URLCheckResult, error) {
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
			log.Printf("[GitLab DEBUG] URL: %s - Initial population: Error parsing URL: %v", rawURL, err)
			continue
		} else {
			result.TargetHostname = parsedURL.Hostname()
		}

		log.Printf("[GitLab] Making direct request to %s", rawURL)
		result.DirectRequest = util.MakeHTTPRequest(ctx, "GET", rawURL, false)
		if result.DirectRequest.Error != "" {
			log.Printf("[GitLab] Direct request error for %s: %s", rawURL, result.DirectRequest.Error)
		}

		if result.TargetHostname != "" {
			geoLoc, resolvedIP, geoErr := util.ResolveHostAndGetGeoLocation(result.TargetHostname)
			if geoErr == nil {
				result.TargetResolvedIP = resolvedIP.String()
				result.TargetGeoCountry = geoLoc.CountryCode
				result.TargetGeoRegion = geoLoc.RegionName
			} else {
				log.Printf("[GitLab] Warning: Could not get GeoIP for %s: %v", result.TargetHostname, geoErr)
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
		log.Printf("[GitLab] No valid URLs with successfully parsed hostnames to process.")
		return allResults, nil
	}

	for i := 0; i < len(validURLsForPipeline); i += gitlabPipelineURLBatchSize {
		end := i + gitlabPipelineURLBatchSize
		if end > len(validURLsForPipeline) {
			end = len(validURLsForPipeline)
		}
		currentBatchURLs := validURLsForPipeline[i:end]

		log.Printf("[GitLab] Processing batch %d, URLs: %d. Batch: %v", (i/gitlabPipelineURLBatchSize)+1, len(currentBatchURLs), currentBatchURLs)

		batchTargetURLString := strings.Join(currentBatchURLs, ",")
		runIDTag := fmt.Sprintf("newtowner-batch-%s-%d", util.SanitizeFilename(p.ProjectID), time.Now().UnixNano())

		pipelineAPIVars := []*gitlab.PipelineVariableOptions{
			{Key: gitlab.Ptr("TARGET_URLS"), Value: gitlab.Ptr(batchTargetURLString)},
			{Key: gitlab.Ptr("RUN_ID_TAG"), Value: gitlab.Ptr(runIDTag)},
		}

		var pipelineInfo *gitlab.Pipeline
		var triggerErr error

		log.Printf("[GitLab] Triggering pipeline with Trigger Token for project %s on ref %s (tag %s)", p.ProjectID, p.PipelineRef, runIDTag)

		triggerVariables := make(map[string]string)
		for _, v := range pipelineAPIVars {
			if v.Key != nil && v.Value != nil {
				triggerVariables[*v.Key] = *v.Value
			}
		}

		// Trigger the pipeline
		triggerOpts := &gitlab.RunPipelineTriggerOptions{
			Token:     gitlab.Ptr(p.PipelineTriggerToken),
			Ref:       gitlab.Ptr(p.PipelineRef),
			Variables: triggerVariables,
		}
		pipelineInfo, _, triggerErr = p.client.PipelineTriggers.RunPipelineTrigger(p.ProjectID, triggerOpts, gitlab.WithContext(ctx))

		if triggerErr != nil {
			dispatchErrorMsg := fmt.Sprintf("Failed to trigger GitLab pipeline (tag %s): %v", runIDTag, triggerErr)
			log.Printf("[GitLab ERROR] %s", dispatchErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok && res.Error == "" {
					res.Error = dispatchErrorMsg
				}
			}
			continue
		}

		log.Printf("[GitLab] Pipeline %d triggered. URL: %s", pipelineInfo.ID, pipelineInfo.WebURL)
		for _, rawURL := range currentBatchURLs {
			if res, ok := resultsMap[rawURL]; ok {
				res.ProviderPipelineDetails.PipelineID = pipelineInfo.ID
				res.ProviderPipelineDetails.PipelineURL = pipelineInfo.WebURL
				res.ProviderPipelineDetails.JobName = p.ArtifactJobName
			}
		}

		// Poll for Pipeline Completion
		log.Printf("[GitLab] Polling for pipeline %d completion (tag %s)...", pipelineInfo.ID, runIDTag)
		completedPipeline, pollErr := p.pollForPipelineCompletion(ctx, pipelineInfo.ID)
		if pollErr != nil {
			pollErrorMsg := fmt.Sprintf("Error waiting for GitLab pipeline %d (tag %s) to complete: %v", pipelineInfo.ID, runIDTag, pollErr)
			log.Printf("[GitLab ERROR] %s", pollErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = pollErrorMsg
					}
					res.ProviderRequest.Error = pollErrorMsg
				}
			}
			continue
		}

		log.Printf("[GitLab] Pipeline %d (tag %s) completed with status: %s", completedPipeline.ID, runIDTag, completedPipeline.Status)

		if completedPipeline.Status != "success" {
			pipelineStatusErrorMsg := fmt.Sprintf("GitLab pipeline %d (tag %s) did not succeed. Status: %s. URL: %s", completedPipeline.ID, runIDTag, completedPipeline.Status, completedPipeline.WebURL)
			log.Printf("[GitLab ERROR] %s", pipelineStatusErrorMsg)
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

		// Download and Parse Artifacts for the current batch
		log.Printf("[GitLab] Downloading and parsing artifacts for pipeline %d, job '%s' (tag %s)", completedPipeline.ID, p.ArtifactJobName, runIDTag)
		actionResultsMap, downloadedArtifactJobID, artifactErr := p.downloadAndParseArtifactsBatch(ctx, completedPipeline.ID, p.ArtifactJobName)
		if artifactErr != nil {
			artifactErrorMsg := fmt.Sprintf("Failed to download/parse artifact for pipeline %d, job '%s' (tag %s): %v", completedPipeline.ID, p.ArtifactJobName, runIDTag, artifactErr)
			log.Printf("[GitLab ERROR] %s", artifactErrorMsg)
			for _, rawURL := range currentBatchURLs {
				if res, ok := resultsMap[rawURL]; ok {
					if res.Error == "" {
						res.Error = artifactErrorMsg
					}
					res.ProviderRequest.Error = artifactErrorMsg
					if downloadedArtifactJobID != -1 {
						res.ProviderPipelineDetails.JobID = downloadedArtifactJobID
					}
				}
			}
			continue // Move to the next batch
		}

		log.Printf("[GitLab DEBUG] Batch tag %s - Parsed artifact results from job %d. Found %d results in map.", runIDTag, downloadedArtifactJobID, len(actionResultsMap))

		// Process results for each URL
		for _, rawURL := range currentBatchURLs {
			result := resultsMap[rawURL]
			result.ProviderPipelineDetails.JobID = downloadedArtifactJobID

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
					log.Printf("[GitLab] Skipping comparison for %s due to provider script error: %s", rawURL, result.ProviderRequest.Error)
				} else {
					log.Printf("[GitLab] Skipping comparison for %s due to direct request error: %s", rawURL, result.DirectRequest.Error)
				}

				if result.Error == "" && result.ProviderRequest.Error != "" {
					result.Error = fmt.Sprintf("Provider script error for %s: %s", rawURL, result.ProviderRequest.Error)
				}

			} else {
				providerNoResultMsg := fmt.Sprintf("Provider result not found in artifact for URL: %s (pipeline %d, job %d, tag %s)", rawURL, completedPipeline.ID, downloadedArtifactJobID, runIDTag)
				log.Printf("[GitLab WARN] %s", providerNoResultMsg)
				if result.Error == "" {
					result.Error = providerNoResultMsg
				}
				result.ProviderRequest.Error = providerNoResultMsg
			}
		}
	}

	log.Printf("[GitLab DEBUG] Completed processing all batches. Total results: %d", len(allResults))
	return allResults, nil
}
