package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/nissbom"
)

const maxNISInput = 64 << 20

// exportNISSBOM writes the NIS-SBOM 1.0 table of a collected CycloneDX SBOM.
func exportNISSBOM(args []string) int {
	flags := flag.NewFlagSet("nis-sbom", flag.ContinueOnError)
	sbom := flags.String("sbom", "", "collected CycloneDX JSON, such as sbom.cdx.json")
	output := flags.String("output", "", "new CSV path")
	var o nissbom.Options
	flags.StringVar(&o.Organization, "organization", "", "organization name that starts the SBOM ID")
	flags.IntVar(&o.Sequence, "sequence", 1, "serial number that ends the SBOM ID, 1 to 999999")
	flags.StringVar(&o.Product, "product", "", "product name, by default the scanned target recorded in the SBOM")
	flags.StringVar(&o.ProductVersion, "product-version", "", "product version")
	flags.StringVar(&o.Author, "author", "", "SBOM author name, by default the collector and its version")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *sbom == "" || *output == "" {
		return 2
	}
	err := func() error {
		in, err := evidencefile.Open(*sbom)
		if err != nil {
			return fmt.Errorf("cannot open the SBOM: %w", err)
		}
		defer in.Close()
		if st, err := in.Stat(); err != nil || !st.Mode().IsRegular() {
			return errors.New("the SBOM must be a regular file")
		}
		raw, err := io.ReadAll(io.LimitReader(in, maxNISInput+1))
		if err != nil || len(raw) > maxNISInput {
			return errors.New("SBOM read failed or exceeded 64 MiB")
		}
		rows, err := nissbom.Rows(raw, o)
		if err != nil {
			return err
		}
		// Exclusive creation never overwrites an earlier result.
		out, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		err = nissbom.Write(out, rows)
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(*output)
		}
		return err
	}()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println(*output)
	return 0
}
