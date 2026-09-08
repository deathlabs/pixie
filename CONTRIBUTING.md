# Contributing

## Updating Pixie's Go Structs to Match the Latest XCCDF Schema 
There is a Makefile at the root of the repository that automates the process of updating Pixie's Go structs to match the latest XCCDF schema. The steps below describe how to use it. 

**Step 1.** Install Go. There's two resources we recommend using: [Go's official documentation](https://go.dev/dl/) or [the DevSecOps Cookbook](https://cyberphor.github.io/devsecops-cookbook/setup/#install-go).

**Step 2.** Install `gocomply_xsd2go`. This is a tool for converting XML Schema Definitions into Go code.
```bash
go install github.com/gocomply/xsd2go/cli/gocomply_xsd2go@latest
```

**Step 3.** Install Make. 
```bash
sudo apt install make
```

**Step 4.** Run the provided Makefile. The `update-models` target will clone the OpenSCAP GitHub repository, run `gocomply_xsd2go` against the XSDs OpenSCAP has (i.e., produce Go structs that implement the latest XCCDF schema), and then delete the files downloaded. 
```bash
make update-models
```
