package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/nfvcsd/terraform-provider-iboss/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// Published on the public Terraform Registry as nfvcsd/iboss; see RELEASING.md.
		Address:         "registry.terraform.io/nfvcsd/iboss",
		Debug:           debug,
		ProtocolVersion: 6,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
