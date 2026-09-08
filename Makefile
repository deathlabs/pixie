# ---------------------------------------------------------
# Set the default target.
# ---------------------------------------------------------

.DEFAULT_GOAL := build
VERSION := $(shell date +%Y-%m-%d-%H%M%S)

# ---------------------------------------------------------
# Build the artifact.
# ---------------------------------------------------------

.PHONY: build
.SILENT: build

build:
	go install -ldflags="-s -w -X 'github.com/deathlabs/pixie/cmd.version=$(VERSION)'" .

# ---------------------------------------------------------
# Update dependencies.
# ---------------------------------------------------------

.PHONY: update
.SILENT: update

update:
	go get -u ./...
	go mod tidy

# ---------------------------------------------------------
# Update Go models.
# ---------------------------------------------------------

.PHONY: update-models
.SILENT: update-models

update-models:
	git clone --depth 1 https://github.com/OpenSCAP/openscap.git &&\
	gocomply_xsd2go convert \
  		--xmlns-override=http://cpe.mitre.org/language/2.0=cpe_language \
  		openscap/schemas/xccdf/1.2/xccdf_1.2.xsd \
  		github.com/deathlabs/pixie \
  		models/xccdf &&\
	rm -rf openscap
