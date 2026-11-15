package collect

import (
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/staticjs"
)

const javascriptSPDXIDPrefix = "SPDXRef-KODA-JavaScript-"

func AddStaticJavaScript(s *sbom.SBOM, components []staticjs.Component) {
	for _, component := range components {
		locations := file.NewLocationSet()
		for _, path := range component.Locations {
			locations.Add(file.NewLocation(path))
		}
		entry := pkg.Package{
			Name: component.Name, Version: component.Version, PURL: component.PURL,
			Type: pkg.NpmPkg, Language: pkg.JavaScript, FoundBy: staticjs.Collector, Locations: locations,
		}
		entry.SetID()
		entry.OverrideID(artifact.ID(javascriptSPDXIDPrefix + strings.TrimPrefix(string(entry.ID()), "SPDXRef-")))
		s.Artifacts.Packages.Add(entry)
	}
}
