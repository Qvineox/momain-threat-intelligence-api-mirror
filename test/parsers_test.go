package test

import (
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParsers(t *testing.T) {
	t.Run("ip extraction function test", func(t *testing.T) {
		require.Equal(t, "", blacklistEntities.ExtractIPFromPattern(""))
		require.Equal(t, "10.10.10.10", blacklistEntities.ExtractIPFromPattern("//10.10.10.10"))
		require.Equal(t, "10.10.10.10", blacklistEntities.ExtractIPFromPattern("//10.10.10.10/path/to/page.html"))
		require.Equal(t, "10.10.10.10", blacklistEntities.ExtractIPFromPattern("//10.10.10.10/path/to/page.html&ip=20.20.20.20"))
		require.Equal(t, "", blacklistEntities.ExtractIPFromPattern("http[:]//www.supernetforme.com/dupe.php?q=2075.2075.300.0.0.0c863a40e7fb424d28afef64ebdb5f95af2cd1b0f476c2ec57ec8e63461e02d4.1.1030449"))
	})
}
