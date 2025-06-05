package aws

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"newtowner/internal/util"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSDKConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type URLCheckResult struct {
	URL                string
	Error              string
	DirectRequest      util.RequestDetails
	APIGatewayRequest  util.RequestDetails
	Comparison         util.ComparisonResult
	PotentialBypass    bool
	BypassReason       string
	APIGatewayRegion   string
	APIGatewayID       string
	APIGatewayEndpoint string
	TargetHostname     string
	TargetResolvedIP   string
	TargetGeoCountry   string
	TargetGeoRegion    string
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
	return r.APIGatewayRequest
}

func (r URLCheckResult) GetProviderDisplayName() string {
	return "AWS API Gateway Request"
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.APIGatewayID == "" {
		return fmt.Sprintf("Region: %s, Status: API Gateway not available/created", r.APIGatewayRegion)
	}
	return fmt.Sprintf("Region: %s, ID: %s", r.APIGatewayRegion, r.APIGatewayID)
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
	return r.Error != "" || r.APIGatewayID == "" || r.DirectRequest.Error != "" || r.APIGatewayRequest.Error != ""
}

type Provider struct {
	cfg                   aws.Config
	initialRegion         string
	regionsToTest         []string
	ec2Client             *ec2.Client
	determineRegionPerURL bool
}

func NewProvider(ctx context.Context, accessKeyID, secretAccessKey, regionFlagValue string, allRegionsFlag bool) (*Provider, error) {
	var cfgOpts []func(*awsSDKConfig.LoadOptions) error

	if accessKeyID != "" && secretAccessKey != "" {
		cfgOpts = append(cfgOpts, awsSDKConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")))
	} else {
		log.Println("AWS Access Key ID or Secret AccessKey not provided. Relying on default credential chain.")
	}

	if regionFlagValue != "" {
		cfgOpts = append(cfgOpts, awsSDKConfig.WithRegion(regionFlagValue))
		log.Printf("AWS SDK will be configured with specified region: %s", regionFlagValue)
	} else {
		log.Println("No --region flag specified. AWS SDK will attempt to auto-detect its default region.")
	}

	loadedCfg, err := awsSDKConfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading AWS SDK config: %w", err)
	}

	resolvedSDKRegion := loadedCfg.Region
	log.Printf("AWS SDK initial configuration resolved to region: %s (this may be from --region, env, or AWS config file)", resolvedSDKRegion)

	provider := &Provider{
		cfg:           loadedCfg,
		initialRegion: resolvedSDKRegion,
		ec2Client:     ec2.NewFromConfig(loadedCfg),
	}

	if allRegionsFlag {
		log.Println("Fetching all available AWS regions for --all-regions...")
		descRegionsOutput, err := provider.ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
		if err != nil {
			return nil, fmt.Errorf("failed to describe AWS regions: %w", err)
		}
		for _, r := range descRegionsOutput.Regions {
			if r.RegionName != nil && r.OptInStatus != nil && (*r.OptInStatus == "opt-in-not-required" || *r.OptInStatus == "opted-in") {
				provider.regionsToTest = append(provider.regionsToTest, *r.RegionName)
			}
		}
		if len(provider.regionsToTest) == 0 {
			log.Println("No available regions found for --all-regions. Check AWS account/opt-in status.")
			if provider.initialRegion != "" {
				log.Printf("Falling back to testing in initialRegion: %s due to no regions from --all-regions", provider.initialRegion)
				provider.regionsToTest = []string{provider.initialRegion}
			} else {
				return nil, fmt.Errorf("--all-regions selected but no regions found and no fallback initial region resolved by SDK")
			}
		} else {
			log.Printf("Found %d regions to test for --all-regions: %v", len(provider.regionsToTest), provider.regionsToTest)
		}
	} else if regionFlagValue != "" {
		if resolvedSDKRegion == "" {
			log.Printf("Warning: --region %s was specified, but SDK could not resolve it. Check region name.", regionFlagValue)
			return nil, fmt.Errorf("specified --region %s could not be resolved by AWS SDK", regionFlagValue)
		}
		provider.regionsToTest = []string{resolvedSDKRegion}
		log.Printf("Testing in specified --region: %s", resolvedSDKRegion)
	} else {
		provider.determineRegionPerURL = true
		log.Println("No specific AWS region or --all-regions flag provided. Will attempt smart region detection per URL.")
		if provider.initialRegion == "" {
			log.Println("Warning: Smart region detection mode, but SDK did not resolve a default initialRegion. Geolocation must succeed.")
		}
	}

	return provider, nil
}

func (p *Provider) getClientForRegion(targetRegion string) *apigateway.Client {
	return apigateway.NewFromConfig(p.cfg, func(o *apigateway.Options) {
		o.Region = targetRegion
	})
}

// checkurls will iterate through urls, resolve them, and perform checks via api gateway
// if --all-regions was set, it iterates through all fetched regions for each url.
func (p *Provider) CheckURLs(urls []string) ([]URLCheckResult, error) {
	log.Printf("AWS Provider (v1 REST API): Checking %d URLs. Mode: %s", len(urls), func() string {
		if p.determineRegionPerURL {
			return fmt.Sprintf("smart geo-detection (1 region per URL, fallback: %s)", p.initialRegion)
		}
		if len(p.regionsToTest) > 1 {
			return fmt.Sprintf("%d regions from --all-regions", len(p.regionsToTest))
		}
		if len(p.regionsToTest) == 1 {
			return fmt.Sprintf("specified region: %s", p.regionsToTest[0])
		}
		return "unknown (error in region setup)"
	}())

	ctx := context.Background()
	allResults := make([]URLCheckResult, 0)
	const stageName = "ProxyStage"

	for _, rawURL := range urls {
		log.Printf("Processing URL: %s", rawURL)
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			allResults = append(allResults, URLCheckResult{URL: rawURL, Error: fmt.Sprintf("Error parsing URL: %v", err)})
			// go to next url
			continue
		}

		baseTargetHostname := parsedURL.Hostname()
		if baseTargetHostname == "" {
			allResults = append(allResults, URLCheckResult{URL: rawURL, Error: "Could not extract hostname from URL.", TargetHostname: baseTargetHostname})
			// go to next url
			continue
		}
		log.Printf("  Hostname: %s", baseTargetHostname)

		// geo-location and direct request are done once per URL
		var targetResolvedIP, targetGeoCountry, targetGeoRegionName string
		geoLoc, resolvedIP, geoErr := util.ResolveHostAndGetGeoLocation(baseTargetHostname)
		if geoErr != nil {
			log.Printf("  Warning: Error resolving host or getting geolocation for %s: %v", baseTargetHostname, geoErr)
		} else {
			targetResolvedIP = resolvedIP.String()
			targetGeoCountry = geoLoc.CountryCode
			targetGeoRegionName = geoLoc.RegionName
			log.Printf("  Resolved IP: %s, Country: %s, GeoLocation (City/Area): %s", resolvedIP.String(), geoLoc.CountryCode, geoLoc.RegionName)
		}

		log.Printf("    Making direct request to %s (once per URL)", rawURL)
		directRequestDetails := util.MakeHTTPRequest(ctx, "GET", rawURL, false)
		if directRequestDetails.Error != "" {
			log.Printf("      Direct request error: %s", directRequestDetails.Error)
		} else {
			log.Printf("      Direct request to %s completed. Status: %d, Body SHA256: %s, Time: %d MS", rawURL, directRequestDetails.StatusCode, directRequestDetails.BodySHA256, directRequestDetails.ResponseTime)
		}

		regionsForThisURL := p.regionsToTest
		if p.determineRegionPerURL {
			determinedRegion, err := util.GetAWSRegionFromGeo(targetGeoCountry, targetGeoRegionName, p.initialRegion)
			if err != nil {
				log.Printf("  Smart region detection failed for %s (%s, %s): %v. Skipping AWS check for this URL.", rawURL, targetGeoCountry, targetGeoRegionName, err)
				result := URLCheckResult{
					URL: rawURL, Error: fmt.Sprintf("AWS region auto-detection failed: %v", err),
					DirectRequest: directRequestDetails, TargetHostname: baseTargetHostname, TargetResolvedIP: targetResolvedIP,
					TargetGeoCountry: targetGeoCountry, TargetGeoRegion: targetGeoRegionName,
				}
				allResults = append(allResults, result)
				// go to next url
				continue
			}
			regionsForThisURL = []string{determinedRegion}
			log.Printf("  Smartly determined AWS region for %s: %s", rawURL, determinedRegion)
		}

		if len(regionsForThisURL) == 0 {
			log.Printf("  No AWS regions to test for URL %s (config issue or --all-regions yielded none). Skipping AWS checks.", rawURL)
			result := URLCheckResult{
				URL: rawURL, Error: "No AWS regions configured or determined for testing this URL.",
				DirectRequest: directRequestDetails, TargetHostname: baseTargetHostname, TargetResolvedIP: targetResolvedIP,
				TargetGeoCountry: targetGeoCountry, TargetGeoRegion: targetGeoRegionName,
			}
			allResults = append(allResults, result)
			// go to next url
			continue
		}

		for _, currentRegion := range regionsForThisURL {
			log.Printf("    Testing URL %s in AWS region: %s", rawURL, currentRegion)
			currentResult := URLCheckResult{
				URL:              rawURL,
				APIGatewayRegion: currentRegion,
				TargetHostname:   baseTargetHostname,
				TargetResolvedIP: targetResolvedIP,
				TargetGeoCountry: targetGeoCountry,
				TargetGeoRegion:  targetGeoRegionName,
				DirectRequest:    directRequestDetails,
			}

			regionSpecificClient := p.getClientForRegion(currentRegion)

			var apiID string
			apiID, apiInvokeBaseURL, createErr := p.createAPIGatewayV1(ctx, regionSpecificClient, currentRegion, rawURL, currentResult.TargetHostname, stageName)
			currentResult.APIGatewayID = apiID

			currentAPIDForDefer := apiID
			defer func(idToDel string, regionToDel string, clientForDelete *apigateway.Client) {
				if idToDel != "" {
					log.Printf("    Attempting to delete API Gateway v1 ID %s in region %s (deferred call)...", idToDel, regionToDel)
					if delErr := p.deleteAPIGatewayV1(context.Background(), clientForDelete, regionToDel, idToDel); delErr != nil {
						log.Printf("      Error deleting API Gateway v1 ID %s in region %s: %v", idToDel, regionToDel, delErr)
					} else {
						log.Printf("      Successfully initiated deletion of API Gateway v1 ID %s in region %s", idToDel, regionToDel)
					}
				}
			}(currentAPIDForDefer, currentRegion, regionSpecificClient)

			if createErr != nil {
				currentResult.Error = fmt.Sprintf("Error creating API Gateway v1 in region %s: %v", currentRegion, createErr)
				log.Printf("    Error creating API Gateway v1 for %s in region %s: %v.", rawURL, currentRegion, createErr)
				allResults = append(allResults, currentResult)
				continue
			}
			log.Printf("      Successfully created API Gateway v1 in region %s: ID %s", currentRegion, currentResult.APIGatewayID)
			currentResult.APIGatewayEndpoint = fmt.Sprintf("%s/%s", apiInvokeBaseURL, stageName)

			var apiGatewayRequestURLBuilder strings.Builder
			apiGatewayRequestURLBuilder.WriteString(currentResult.APIGatewayEndpoint)
			if parsedURL.RequestURI() != "" && parsedURL.RequestURI() != "/" {
				if strings.HasSuffix(currentResult.APIGatewayEndpoint, "/") {
					if strings.HasPrefix(parsedURL.RequestURI(), "/") {
						apiGatewayRequestURLBuilder.WriteString(parsedURL.RequestURI()[1:])
					} else {
						apiGatewayRequestURLBuilder.WriteString(parsedURL.RequestURI())
					}
				} else {
					if !strings.HasPrefix(parsedURL.RequestURI(), "/") {
						apiGatewayRequestURLBuilder.WriteString("/")
					}
					apiGatewayRequestURLBuilder.WriteString(parsedURL.RequestURI())
				}
			} else if !strings.HasSuffix(currentResult.APIGatewayEndpoint, "/") && (parsedURL.RequestURI() == "" || parsedURL.RequestURI() == "/") {
				apiGatewayRequestURLBuilder.WriteString("/")
			}
			finalAPIGatewayRequestURL := apiGatewayRequestURLBuilder.String()

			log.Printf("    Making request via API Gateway v1 in region %s: %s (proxies to %s)", currentRegion, finalAPIGatewayRequestURL, rawURL)
			currentResult.APIGatewayRequest = util.MakeHTTPRequest(ctx, "GET", finalAPIGatewayRequestURL, true)
			if currentResult.APIGatewayRequest.Error != "" {
				log.Printf("      API Gateway request error: %s", currentResult.APIGatewayRequest.Error)
				currentResult.Error = fmt.Sprintf("%s; API GW request error: %v", currentResult.Error, currentResult.APIGatewayRequest.Error)
			} else {
				log.Printf(
					"API Gateway request to %s completed. Status: %d, Body SHA256: %s, Time: %d",
					finalAPIGatewayRequestURL,
					currentResult.APIGatewayRequest.StatusCode,
					currentResult.APIGatewayRequest.BodySHA256,
					currentResult.APIGatewayRequest.ResponseTime,
				)
			}

			comparisonResult, potentialBypass, bypassReason := util.CompareHTTPResponses(currentResult.DirectRequest, currentResult.APIGatewayRequest)
			currentResult.Comparison = comparisonResult
			currentResult.PotentialBypass = potentialBypass
			currentResult.BypassReason = bypassReason

			if currentResult.DirectRequest.Error == "" && currentResult.APIGatewayRequest.Error == "" {
				if potentialBypass {
					log.Printf("      Potential Bypass Detected for %s in region %s: %s", rawURL, currentRegion, bypassReason)
				} else {
					log.Printf("      No significant differences detected for %s in region %s.", rawURL, currentRegion)
				}
			} else {
				log.Printf("      Bypass assessment for %s in region %s (may have errors): %s", rawURL, currentRegion, bypassReason)
			}
			allResults = append(allResults, currentResult)
		}
	}
	return allResults, nil
}

// createAPIGatewayV1 uses the passed region-specific client.
func (p *Provider) createAPIGatewayV1(ctx context.Context, client *apigateway.Client, region string, originalRawURL string, apiNameSuffix string, stageName string) (apiID string, apiInvokeBaseURL string, err error) {
	log.Printf("    Creating v1 REST API in region %s for %s", region, originalRawURL)

	parsedOriginalURL, parseErr := url.Parse(originalRawURL)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse originalRawURL '%s': %w", originalRawURL, parseErr)
	}
	schemeAndHost := fmt.Sprintf("%s://%s", parsedOriginalURL.Scheme, parsedOriginalURL.Host)

	sanitizedSuffix := strings.ReplaceAll(apiNameSuffix, ".", "-")
	sanitizedSuffix = strings.ReplaceAll(sanitizedSuffix, ":", "-")
	restApiName := fmt.Sprintf("newtowner-%s-%d", sanitizedSuffix, time.Now().UnixNano())
	restApiName = restApiName[:min(len(restApiName), 1024)]

	createResp, err := client.CreateRestApi(ctx, &apigateway.CreateRestApiInput{
		Name:        aws.String(restApiName),
		Description: aws.String(fmt.Sprintf("Newtowner v1 proxy for %s", originalRawURL)),
		EndpointConfiguration: &types.EndpointConfiguration{
			Types: []types.EndpointType{types.EndpointTypeRegional},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("CreateRestApi failed: %w", err)
	}
	apiID = *createResp.Id
	log.Printf("      Created REST API ID: %s, Name: %s", apiID, *createResp.Name)

	var rootResourceID string
	getResResp, err := client.GetResources(ctx, &apigateway.GetResourcesInput{RestApiId: aws.String(apiID)})
	if err != nil {
		return apiID, "", fmt.Errorf("GetResources failed for API ID %s: %w", apiID, err)
	}
	for _, item := range getResResp.Items {
		if item.Path != nil && *item.Path == "/" {
			rootResourceID = *item.Id
			break
		}
	}
	if rootResourceID == "" {
		return apiID, "", fmt.Errorf("could not find root resource for API ID %s", apiID)
	}
	log.Printf("      Root Resource ID: %s", rootResourceID)

	log.Printf("      Setting up ANY method for Root Resource ID %s", rootResourceID)
	_, err = client.PutMethod(ctx, &apigateway.PutMethodInput{
		HttpMethod:        aws.String("ANY"),
		ResourceId:        aws.String(rootResourceID),
		RestApiId:         aws.String(apiID),
		AuthorizationType: aws.String("NONE"),
		RequestParameters: map[string]bool{
			"method.request.header.X-My-X-Forwarded-For": false,
		},
	})
	if err != nil {
		return apiID, "", fmt.Errorf("PutMethod on Root resource failed: %w", err)
	}

	log.Printf("      Setting up Integration for Root Resource ID %s", rootResourceID)
	rootIntegrationURI := schemeAndHost + "/"
	_, err = client.PutIntegration(ctx, &apigateway.PutIntegrationInput{
		HttpMethod:            aws.String("ANY"),
		IntegrationHttpMethod: aws.String("ANY"),
		ResourceId:            aws.String(rootResourceID),
		RestApiId:             aws.String(apiID),
		Type:                  types.IntegrationTypeHttpProxy,
		Uri:                   aws.String(rootIntegrationURI),
		RequestParameters: map[string]string{
			"integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For",
		},
	})
	if err != nil {
		return apiID, "", fmt.Errorf("PutIntegration on Root resource failed: %w", err)
	}
	log.Printf("      Root resource ANY method and integration setup complete.")

	log.Printf("      Creating {proxy+} resource under Root ID %s", rootResourceID)
	createProxyResResp, err := client.CreateResource(ctx, &apigateway.CreateResourceInput{
		ParentId:  aws.String(rootResourceID),
		PathPart:  aws.String("{proxy+}"),
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		return apiID, "", fmt.Errorf("CreateResource for {proxy+} failed: %w", err)
	}
	proxyResourceID := *createProxyResResp.Id
	log.Printf("      Created {proxy+} Resource ID: %s", proxyResourceID)

	log.Printf("      Setting up ANY method for {proxy+} Resource ID %s", proxyResourceID)
	_, err = client.PutMethod(ctx, &apigateway.PutMethodInput{
		HttpMethod:        aws.String("ANY"),
		ResourceId:        aws.String(proxyResourceID),
		RestApiId:         aws.String(apiID),
		AuthorizationType: aws.String("NONE"),
		RequestParameters: map[string]bool{
			"method.request.path.proxy":                  false,
			"method.request.header.X-My-X-Forwarded-For": false,
		},
	})
	if err != nil {
		return apiID, "", fmt.Errorf("PutMethod on {proxy+} resource failed: %w", err)
	}

	log.Printf("      Setting up Integration for {proxy+} Resource ID %s", proxyResourceID)
	proxyIntegrationURI := fmt.Sprintf("%s/{proxy}", schemeAndHost)
	_, err = client.PutIntegration(ctx, &apigateway.PutIntegrationInput{
		HttpMethod:            aws.String("ANY"),
		IntegrationHttpMethod: aws.String("ANY"),
		ResourceId:            aws.String(proxyResourceID),
		RestApiId:             aws.String(apiID),
		Type:                  types.IntegrationTypeHttpProxy,
		Uri:                   aws.String(proxyIntegrationURI),
		RequestParameters: map[string]string{
			"integration.request.path.proxy":             "method.request.path.proxy",
			"integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For",
		},
	})
	if err != nil {
		return apiID, "", fmt.Errorf("PutIntegration on {proxy+} resource failed: %w", err)
	}
	log.Printf("      {proxy+} resource setup complete.")

	log.Printf("      Creating deployment for API ID %s with stage '%s'", apiID, stageName)
	_, err = client.CreateDeployment(ctx, &apigateway.CreateDeploymentInput{
		RestApiId: aws.String(apiID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		return apiID, "", fmt.Errorf("CreateDeployment failed for API ID %s: %w", apiID, err)
	}
	log.Printf("      Deployment created.")

	apiInvokeBaseURL = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com", apiID, region)
	log.Printf("    v1 REST API created. ID: %s, Stage: '%s', Base Invoke URL for stage: %s/%s", apiID, stageName, apiInvokeBaseURL, stageName)
	return apiID, apiInvokeBaseURL, nil
}

// deleteAPIGatewayV1 uses the passed region-specific client.
func (p *Provider) deleteAPIGatewayV1(ctx context.Context, client *apigateway.Client, region string, apiID string) error {
	log.Printf("    Deleting v1 REST API ID %s in region %s", apiID, region)
	if apiID == "" {
		log.Printf("      Skipping deletion of empty API ID.")
		return nil
	}
	_, err := client.DeleteRestApi(ctx, &apigateway.DeleteRestApiInput{
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		return fmt.Errorf("failed to delete v1 REST API ID %s in region %s: %w", apiID, region, err)
	}
	log.Printf("      Successfully initiated deletion of v1 REST API ID %s in region %s", apiID, region)
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
