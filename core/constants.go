package core

// ExtractorIntensity defines the intensity level for the crawler.
type ExtractorIntensity string

const (
	// IntensityPassive is the default intensity level.
	IntensityPassive ExtractorIntensity = "passive"
	// IntensityMedium is a medium intensity level.
	IntensityMedium ExtractorIntensity = "medium"
	// IntensityAggressive is an aggressive intensity level.
	IntensityAggressive ExtractorIntensity = "aggressive"
	// IntensityUltra is the highest intensity level for deep crawling.
	IntensityUltra ExtractorIntensity = "ultra"
)