# Use Cases

## Using Generative AI and Pixie to Develop an SRG/STIG
The instructions below demonstrate how generative AI and `pixie` can be used together to produce an SRG for AI. While `pixie` does not require AI, this specific use-case highlights how `pixie` makes it easier to develop and maintain SRGs and STIGs. 

**Step 1.** Download the following documents.  

* [The CCI List from the DOD Cyber Exchange](https://www.cyber.mil/stigs/downloads)  
* [DoD Artificial Intelligence Cybersecurity Risk Management Tailoring Guide](https://www.dmi-ida.org/download-pdf/pdf/AI-CybersecurityRMTailoringGuide.pdf )  

**Step 2.** Feed the documents you downloaded and a YAML file similar to [the one in the examples folder](examples/agentic-ai-infrastructure-srg-xccdf.xml) to your preferred Large Language Model (LLM). In your prompt, request the LLM to generate a new YAML file using the requirements based on Appendix B and the CCI list. 

**Step 3.** Feed the YAML file to `pixie` using the command below. 
```bash
pixie convert yaml -i srg.yaml -o srg-xccdf.xml
```

**Step 4.** Open and use the XML file produced by `pixie` using [STIG Viewer](https://www.cyber.mil/stigs/srg-stig-tools) as desired. 
