package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	groundwork "terraform-provider-groundwork/internal/provider"
)

// Version is set at build time via -ldflags; dev builds report "dev".
var Version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/groundwork/groundwork",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), func() provider.Provider {
		return groundwork.New(Version)
	}, opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
