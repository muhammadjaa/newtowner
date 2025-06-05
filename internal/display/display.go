package display

import (
	"fmt"
	"os"
	"strings"
	"time"

	"newtowner/internal/util"

	"crypto/x509"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"golang.org/x/term"
)

var columnStyle = lipgloss.NewStyle().
	Padding(0, 1).
	Width(85)

// ProviderResultDisplay defines the common methods that any provider's
// URL check result must implement to be displayed by the unified display function.
type ProviderResultDisplay interface {
	GetURL() string
	GetTargetHostname() string
	GetTargetResolvedIP() string
	GetTargetGeoCountry() string
	GetTargetGeoRegion() string

	GetProcessingError() string // Overall error for this URL check by the provider

	GetDirectRequestDetails() util.RequestDetails
	GetProviderRequestDetails() util.RequestDetails

	GetDirectDisplayName() string   // e.g., "Direct Request Details", "SSH/us-east-1", etc.
	GetProviderDisplayName() string // e.g., "API Gateway Request", "GitHub Action Request"
	GetProviderSubDetails() string  // e.g., "Region: us-east-1, ID: xyz", "Workflow Run ID: 12345"

	GetComparisonResult() util.ComparisonResult
	IsPotentialBypass() bool
	GetBypassReason() string

	// ShouldSkipBodyDiff indicates if the body diff section should be skipped.
	ShouldSkipBodyDiff() bool
}

// DisplayStyles holds all the lipgloss styles needed for the unified display function.
type DisplayStyles struct {
	StyleHeader         lipgloss.Style
	StyleSubHeader      lipgloss.Style
	StyleKey            lipgloss.Style
	StyleValue          lipgloss.Style
	StyleError          lipgloss.Style
	StyleSuccess        lipgloss.Style
	StyleBypass         lipgloss.Style
	StyleNoBypass       lipgloss.Style
	StyleCard           lipgloss.Style
	StyleSectionTitle   lipgloss.Style
	StyleTableContainer lipgloss.Style
	StyleDetailHeader   lipgloss.Style
}

var (
	styleHeader    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleSubHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	styleKey       = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleValue     = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	styleError     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleSuccess   = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleBypass    = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("9")).Foreground(lipgloss.Color("15"))
	styleNoBypass  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))

	styleCard = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 1).
			MarginBottom(1)

	styleSectionTitle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("14")).
				MarginTop(1).
				MarginBottom(1).
				Underline(true)

	styleTableContainer = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				Padding(0, 0)

	styleDetailHeader = lipgloss.NewStyle().
				Bold(true).
				MarginBottom(1).
				PaddingBottom(0).
				Border(lipgloss.NormalBorder(), false, false, true, false).
				BorderForeground(lipgloss.Color("244"))
)

// DefaultDisplayStyles provides a default set of styles for displaying results.
var DefaultDisplayStyles = DisplayStyles{
	StyleHeader:         styleHeader,
	StyleSubHeader:      styleSubHeader,
	StyleKey:            styleKey,
	StyleValue:          styleValue,
	StyleError:          styleError,
	StyleSuccess:        styleSuccess,
	StyleBypass:         styleBypass,
	StyleNoBypass:       styleNoBypass,
	StyleCard:           styleCard,
	StyleSectionTitle:   styleSectionTitle,
	StyleTableContainer: styleTableContainer,
	StyleDetailHeader:   styleDetailHeader,
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Helper to format request details lines
func formatRequestLines(req util.RequestDetails, styles DisplayStyles) []string {
	if req.Error != "" {
		return []string{fmt.Sprintf("Error: %s", styles.StyleError.Render(req.Error))}
	}
	lines := []string{
		fmt.Sprintf("%s %d", styles.StyleKey.Bold(true).Render("Status:"), req.StatusCode),
		fmt.Sprintf("%s %s", styles.StyleKey.Bold(true).Render("Body SHA256:"), req.BodySHA256),
		fmt.Sprintf("%s %d MS", styles.StyleKey.Bold(true).Render("Time:"), req.ResponseTime),
	}
	return lines
}

// Helper to build table rows from two columns
func buildTableRows(left, right []string, minRows int) [][]string {
	rows := make([][]string, minRows)
	for i := 0; i < minRows; i++ {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		rows[i] = []string{l, r}
	}
	return rows
}

// Helper to render a side-by-side table
func renderSideBySideTable(headers []string, rows [][]string, baseCellWidth, leftPadding, rightPadding int) string {
	tbl := table.New().
		Headers(headers...).
		Rows(rows...).
		Border(lipgloss.HiddenBorder()).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return lipgloss.NewStyle().PaddingLeft(leftPadding).PaddingRight(rightPadding)
			}
			cellStyle := lipgloss.NewStyle().
				Width(baseCellWidth).
				PaddingLeft(leftPadding).PaddingRight(rightPadding)
			if col == 1 {
				return cellStyle.
					Border(lipgloss.NormalBorder(), false, false, false, true).
					BorderForeground(lipgloss.Color("240"))
			}
			return cellStyle
		})
	return tbl.Render()
}

// formatRequestDetailsTable creates a side-by-side string for direct and provider requests.
func formatRequestDetailsTable(direct util.RequestDetails, provider util.RequestDetails, res ProviderResultDisplay, tableAreaNetWidth int, styles DisplayStyles) string {
	directInfoLines := formatRequestLines(direct, styles)

	providerName := res.GetProviderDisplayName()
	providerSubDetail := res.GetProviderSubDetails()
	providerFullName := providerName
	if providerSubDetail != "" {
		providerFullName = fmt.Sprintf("%s (%s)", providerName, providerSubDetail)
	}

	providerInfoLines := formatRequestLines(provider, styles)
	if provider.Error == "" && provider.URL != "" && provider.URL != direct.URL {
		// Insert Invoked URL at the top if different
		providerInfoLines = append([]string{fmt.Sprintf("%s %s", styles.StyleKey.Bold(true).Render("Invoked URL:"), provider.URL)}, providerInfoLines...)
	}

	headerRow := []string{
		styles.StyleDetailHeader.Render(res.GetDirectDisplayName() + ":"),
		styles.StyleDetailHeader.Render(providerFullName + ":"),
	}

	numDataRows := maxInt(len(directInfoLines), len(providerInfoLines))
	tableDataRows := buildTableRows(directInfoLines, providerInfoLines, numDataRows)

	_, rightPadding, _, leftPadding := columnStyle.GetPadding()
	cellHPadding := leftPadding + rightPadding
	interColumnBorderWidth := 1
	availableWidthForBothCellsContent := tableAreaNetWidth - (2 * cellHPadding) - interColumnBorderWidth
	baseCellWidth := availableWidthForBothCellsContent / 2
	if baseCellWidth < 20 {
		baseCellWidth = 20
	}

	return renderSideBySideTable(headerRow, tableDataRows, baseCellWidth, leftPadding, rightPadding)
}

// certDisplay holds the fields we want to show for a certificate.
type certDisplay struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotValidBefore     string
	NotValidAfter      string
	SignatureAlgorithm string
}

func getCertDisplay(cert *x509.Certificate) certDisplay {
	return certDisplay{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotValidBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
		NotValidAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}
}

func formatCertLines(cert *x509.Certificate, certErr string, compare *x509.Certificate, styles DisplayStyles, isLeft bool) []string {
	if certErr != "" {
		return []string{styles.StyleError.Render(fmt.Sprintf("Error: %s", certErr))}
	}
	if cert == nil {
		return []string{styles.StyleValue.Render("(No certificate details or not an HTTPS request)")}
	}

	display := getCertDisplay(cert)
	var compareDisplay certDisplay
	if compare != nil {
		compareDisplay = getCertDisplay(compare)
	}

	var lines []string
	fields := []struct {
		key   string
		value string
		other string
	}{
		{"Subject", display.Subject, compareDisplay.Subject},
		{"Issuer", display.Issuer, compareDisplay.Issuer},
		{"Serial Number", display.SerialNumber, compareDisplay.SerialNumber},
		{"Not Valid Before", display.NotValidBefore, compareDisplay.NotValidBefore},
		{"Not Valid After", display.NotValidAfter, compareDisplay.NotValidAfter},
		{"Signature Algorithm", display.SignatureAlgorithm, compareDisplay.SignatureAlgorithm},
	}

	for _, f := range fields {
		styledKey := styles.StyleKey.Render(f.key + ":")
		styledVal := styles.StyleValue.Render(f.value)
		if compare != nil && f.value != f.other {
			styledVal = styles.StyleError.Render(f.value)
		}
		lines = append(lines, fmt.Sprintf("%s %s", styledKey, styledVal))
	}
	return lines
}

// formatSSLCertificateComparisonTable creates a side-by-side string for SSL certificate differences.
func formatSSLCertificateComparisonTable(
	directReq util.RequestDetails,
	providerReq util.RequestDetails,
	res ProviderResultDisplay,
	tableAreaNetWidth int,
	styles DisplayStyles,
) string {
	// Parse certificates
	var directCert, providerCert *x509.Certificate
	if directReq.SSLCertificatePEM != "" {
		directCert, _ = util.ParseCertificateFromPEM(directReq.SSLCertificatePEM)
	}
	if providerReq.SSLCertificatePEM != "" {
		providerCert, _ = util.ParseCertificateFromPEM(providerReq.SSLCertificatePEM)
	}

	directLines := formatCertLines(directCert, directReq.SSLCertificateError, providerCert, styles, true)
	providerLines := formatCertLines(providerCert, providerReq.SSLCertificateError, directCert, styles, false)

	// Table headers
	headerRow := []string{
		styles.StyleDetailHeader.Render(res.GetDirectDisplayName() + " SSL Certificate:"),
		styles.StyleDetailHeader.Render(fmt.Sprintf("%s SSL Certificate:", res.GetProviderDisplayName())),
	}

	numDataRows := maxInt(len(directLines), len(providerLines))
	tableDataRows := make([][]string, numDataRows)

	for i := 0; i < numDataRows; i++ {
		var directCell, providerCell string
		if i < len(directLines) {
			directCell = directLines[i]
		}
		if i < len(providerLines) {
			providerCell = providerLines[i]
		}
		tableDataRows[i] = []string{directCell, providerCell}
	}

	_, rightPadding, _, leftPadding := columnStyle.GetPadding()
	cellHPadding := leftPadding + rightPadding
	interColumnBorderWidth := 1
	availableWidthForBothCellsContent := tableAreaNetWidth - (2 * cellHPadding) - interColumnBorderWidth
	baseCellWidth := availableWidthForBothCellsContent / 2
	if baseCellWidth < 20 {
		baseCellWidth = 20
	}

	sslTable := table.New().
		Headers(headerRow...).
		Rows(tableDataRows...).
		Border(lipgloss.HiddenBorder()).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return lipgloss.NewStyle().PaddingLeft(leftPadding).PaddingRight(rightPadding)
			}
			cellStyle := lipgloss.NewStyle().
				Width(baseCellWidth).
				PaddingLeft(leftPadding).PaddingRight(rightPadding)
			if col == 1 {
				return cellStyle.
					Border(lipgloss.NormalBorder(), false, false, false, true).
					BorderForeground(lipgloss.Color("240"))
			}
			return cellStyle
		})

	return sslTable.Render()
}

// formatHeaderComparisonTable creates a side-by-side string for header differences.
func formatHeaderComparisonTable(res ProviderResultDisplay, tableAreaNetWidth int, styles DisplayStyles) string {
	comparison := res.GetComparisonResult()
	directKVs, proxiedKVs, cookies, hasDirect, hasProxied, hasCookies := util.GetFormattedHeaderDiffElements(comparison)

	if !hasDirect && !hasProxied && !hasCookies {
		return fmt.Sprintf("  %s\n", styles.StyleValue.Render("(No unique headers or new cookies to display after filtering.)"))
	}

	var leftColumnData, rightColumnData []string
	if hasDirect {
		leftColumnData = directKVs
	} else {
		leftColumnData = []string{styles.StyleValue.Render("(None)")}
	}

	if hasProxied {
		rightColumnData = append(rightColumnData, proxiedKVs...)
	}
	if hasCookies {
		if hasProxied && len(proxiedKVs) > 0 {
			rightColumnData = append(rightColumnData, "") // Spacer line
		}
		rightColumnData = append(rightColumnData, styles.StyleKey.Render("New Cookies:"))
		rightColumnData = append(rightColumnData, cookies...)
	}
	if !hasProxied && !hasCookies {
		rightColumnData = []string{styles.StyleValue.Render("(None)")}
	}

	numRows := maxInt(len(leftColumnData), len(rightColumnData))
	tableRows := buildTableRows(leftColumnData, rightColumnData, numRows)

	headerRow := []string{
		styles.StyleSubHeader.Render("Unique to Direct Request:"),
		styles.StyleSubHeader.Render(fmt.Sprintf("Differences from %s:", res.GetProviderDisplayName())),
	}

	_, rightPadding, _, leftPadding := columnStyle.GetPadding()
	cellHPadding := leftPadding + rightPadding
	interColumnBorderWidth := 1
	availableWidthForBothCellsContent := tableAreaNetWidth - (2 * cellHPadding) - interColumnBorderWidth
	baseCellWidth := availableWidthForBothCellsContent / 2
	if baseCellWidth < 20 {
		baseCellWidth = 20
	}

	return renderSideBySideTable(headerRow, tableRows, baseCellWidth, leftPadding, rightPadding)
}

// DisplaySingleURLCheckResult takes a result that implements ProviderResultDisplay
// and prints its details in a standardized format using the provided styles.
func DisplaySingleURLCheckResult(idx int, res ProviderResultDisplay, styles DisplayStyles) {
	var sb strings.Builder

	var termWidth int
	var err error
	fd := int(os.Stdout.Fd())
	termWidth, _, err = term.GetSize(fd)
	if err != nil {
		termWidth = 120
	}

	// Ensure a minimum card width based on a percentage of terminal width.
	// Aim for 90% of terminal width but not less than 100 chars,
	cardTargetWidth := int(float64(termWidth) * 0.90)
	if cardTargetWidth < 100 {
		cardTargetWidth = 100
	}
	if cardTargetWidth > 200 { // Max card width to prevent overly wide tables.
		cardTargetWidth = 200
	}

	// Calculate available width for table content within the card.
	// Card paddings:
	_, cardPaddingRight, _, cardPaddingLeft := styles.StyleCard.GetPadding()
	cardHPadding := cardPaddingLeft + cardPaddingRight

	// TableContainer borders (assuming 1px on each side for NormalBorder)
	tableContainerHBorder := 2 // Left and Right border of StyleTableContainer

	// Net width available for the table itself (its cells + cell paddings + inter-cell borders)
	// This is the width the table's content area (columns) should try to fill.
	tableAreaNetWidth := cardTargetWidth - cardHPadding - tableContainerHBorder

	var detailsParts []string
	detailsParts = append(detailsParts, fmt.Sprintf("%s %s", styles.StyleSubHeader.Render(fmt.Sprintf("URL #%d:", idx+1)), styles.StyleValue.Render(res.GetURL())))
	detailsParts = append(detailsParts, fmt.Sprintf("%s %s", styles.StyleKey.Render("Target Host:"), styles.StyleValue.Render(res.GetTargetHostname())))
	detailsParts = append(detailsParts, fmt.Sprintf("%s %s", styles.StyleKey.Render("Resolved IP:"), styles.StyleValue.Render(res.GetTargetResolvedIP())))
	detailsParts = append(detailsParts, fmt.Sprintf("%s %s", styles.StyleKey.Render("Geo Country:"), styles.StyleValue.Render(res.GetTargetGeoCountry())))
	detailsParts = append(detailsParts, fmt.Sprintf("%s %s", styles.StyleKey.Render("Geo Region:"), styles.StyleValue.Render(res.GetTargetGeoRegion())))

	// Join parts with a consistent separator for a "tab-like" feel
	// Using "\t" as a separator.
	fullDetailsLine := strings.Join(detailsParts, "\t")
	sb.WriteString(lipgloss.NewStyle().MarginLeft(2).Render(fullDetailsLine) + "\n")

	// Handle Processing Error on its own line(s)
	if processingErr := res.GetProcessingError(); processingErr != "" {
		errorKey := styles.StyleKey.Render("Processing Error:")
		errorVal := styles.StyleError.Render(processingErr)
		errorLine := fmt.Sprintf("%s %s", errorKey, errorVal)
		sb.WriteString(lipgloss.NewStyle().MarginLeft(2).Render(errorLine) + "\n")
	}

	// --- Direct & Provider Request Details Table ---
	tableOutput := formatRequestDetailsTable(
		res.GetDirectRequestDetails(),
		res.GetProviderRequestDetails(),
		res,
		tableAreaNetWidth,
		styles,
	)
	sb.WriteString(styles.StyleTableContainer.Render(tableOutput) + "\n")

	// --- SSL Certificate Comparison Table ---
	directReqDetails := res.GetDirectRequestDetails()
	providerReqDetails := res.GetProviderRequestDetails()

	if (directReqDetails.SSLCertificatePEM != "" || directReqDetails.SSLCertificateError != "") ||
		(providerReqDetails.SSLCertificatePEM != "" || providerReqDetails.SSLCertificateError != "") {

		sb.WriteString(styles.StyleSectionTitle.Render("SSL Certificate Comparison:") + "\n")
		sslTableOutput := formatSSLCertificateComparisonTable(
			directReqDetails,
			providerReqDetails,
			res,
			tableAreaNetWidth,
			styles,
		)
		sb.WriteString(styles.StyleTableContainer.Render(sslTableOutput) + "\n")
	}

	// --- Full Response Diff ---
	sb.WriteString(styles.StyleSectionTitle.Render("Full Response Diff:") + "\n")
	comparison := res.GetComparisonResult() // Needed for summary sections below
	directRequestDetails := res.GetDirectRequestDetails()
	providerRequestDetails := res.GetProviderRequestDetails()

	// Always generate full response strings for diffing.
	// util.FormatFullResponse handles cases where details.Error is not empty.
	directFullResponse := util.FormatFullResponse(directRequestDetails)
	providerFullResponse := util.FormatFullResponse(providerRequestDetails)

	// Check if we should skip the diff display entirely based on provider-specific logic
	// (e.g. provider setup error that makes any comparison meaningless).
	// This is different from one of the HTTP requests having an error.
	if res.ShouldSkipBodyDiff() && directRequestDetails.Error == "" && providerRequestDetails.Error == "" {
		// This case implies ShouldSkipBodyDiff was true for reasons other than request errors
		// (e.g. a provider-level setup issue reported via res.GetProcessingError()
		// which might also be reflected in res.ShouldSkipBodyDiff() logic).
		sb.WriteString(fmt.Sprintf("    %s\n", styles.StyleKey.Render("Skipping full response diff as indicated by provider (e.g., setup issue or explicit skip).")))
	} else {
		diffOut, diffErr := util.GenerateDiffOutput(directFullResponse, providerFullResponse)
		if diffErr != nil {
			sb.WriteString(fmt.Sprintf("    %s %s\n", styles.StyleKey.Render("Error generating full response diff:"), styles.StyleError.Render(diffErr.Error())))
			// Fallback to sequential display if diff generation itself failed
			sb.WriteString(styles.StyleKey.Render("Direct Request Output (fallback):\n"))
			sb.WriteString(util.IndentString(directFullResponse, "    ") + "\n")
			sb.WriteString(styles.StyleKey.Render("Provider Request Output (fallback):\n"))
			sb.WriteString(util.IndentString(providerFullResponse, "    ") + "\n")
		} else if strings.TrimSpace(diffOut) == "" {
			if directRequestDetails.Error == "" && providerRequestDetails.Error == "" {
				// Both were successful, and diff is empty: they are identical.
				sb.WriteString(fmt.Sprintf("    %s\n", styles.StyleSuccess.Render("Full responses (including headers and body) appear identical.")))
			} else if directFullResponse == providerFullResponse {
				// Errors might be identical, or one is an error and the other is an identical string (unlikely but possible)
				sb.WriteString(fmt.Sprintf("    %s\n", styles.StyleValue.Render("Contents are identical.")))
				if directRequestDetails.Error != "" {
					sb.WriteString(fmt.Sprintf("    %s %s\n", styles.StyleKey.Render("Note: Direct request had an error:"), styles.StyleError.Render(directRequestDetails.Error)))
				}
				if providerRequestDetails.Error != "" {
					sb.WriteString(fmt.Sprintf("    %s %s\n", styles.StyleKey.Render("Note: Provider request had an error:"), styles.StyleError.Render(providerRequestDetails.Error)))
				}
			} else {
				// Diff is empty, but raw strings differ, and at least one had an error or they were just different.
				// This implies that GenerateDiffOutput found no *visual* differences.
				sb.WriteString(fmt.Sprintf("    %s\n", styles.StyleValue.Render("Full responses differ but diff output is empty; likely subtle differences or primarily error messages.")))
				sb.WriteString(styles.StyleKey.Render("Direct Request Output (raw):\n"))
				sb.WriteString(util.IndentString(directFullResponse, "    ") + "\n")
				sb.WriteString(styles.StyleKey.Render("Provider Request Output (raw):\n"))
				sb.WriteString(util.IndentString(providerFullResponse, "    ") + "\n")
			}
		} else {
			// Diff output is present, render it.
			sb.WriteString(diffOut)
			if !strings.HasSuffix(diffOut, "\n") {
				sb.WriteString("\n")
			}
		}
	}

	// --- Comparison Summary ---
	sb.WriteString(styles.StyleSectionTitle.Render("Comparison Summary:") + "\n")
	statusMatchStr := styles.StyleError.Render("No")
	if comparison.StatusCodesMatch {
		statusMatchStr = styles.StyleSuccess.Render("Yes")
	}
	bodyMatchStr := styles.StyleError.Render("No")
	if comparison.BodySHA256Match {
		bodyMatchStr = styles.StyleSuccess.Render("Yes")
	}
	sb.WriteString(fmt.Sprintf("    %s %s, %s %s\n",
		styles.StyleKey.Render("Status Codes Match:"), statusMatchStr,
		styles.StyleKey.Render("Body SHA256 Match:"), bodyMatchStr,
	))

	notesStyle := lipgloss.NewStyle().Width(columnStyle.GetWidth()*2 + columnStyle.GetPaddingLeft() + columnStyle.GetPaddingRight() + 4).PaddingLeft(4)
	sb.WriteString(fmt.Sprintf("    %s %s\n", styles.StyleKey.Render("Notes:"), notesStyle.Render(comparison.Notes)))

	sb.WriteString(styles.StyleSectionTitle.Render("Bypass Assessment:") + "\n")
	if res.IsPotentialBypass() {
		sb.WriteString(fmt.Sprintf("  %s %s\n", styles.StyleBypass.Render("Potential Bypass Detected:"), styles.StyleError.Render(res.GetBypassReason())))
	} else if res.GetDirectRequestDetails().Error == "" && res.GetProviderRequestDetails().Error == "" && !res.ShouldSkipBodyDiff() {
		if strings.TrimSpace(res.GetBypassReason()) == "" || res.GetBypassReason() == "No significant differences detected in status, body, header keys, or new cookies (after filtering)." {
			sb.WriteString(fmt.Sprintf("  %s\n", styles.StyleNoBypass.Render("No bypass detected.")))
		} else {
			sb.WriteString(fmt.Sprintf("  %s %s\n", styles.StyleKey.Render("Differences Noted:"), notesStyle.Render(res.GetBypassReason())))
		}
	} else {
		sb.WriteString(fmt.Sprintf("  %s %s\n", styles.StyleKey.Render("Assessment Details:"), notesStyle.Render(res.GetBypassReason())))
	}

	// Render the card with the calculated width
	finalCardStyle := styles.StyleCard.Copy().Width(cardTargetWidth)
	fmt.Println(finalCardStyle.Render(sb.String()))
}
