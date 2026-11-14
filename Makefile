build:
	chmod +x bin/netconf-audit

test:
	tclsh tests/test.tcl

sample: build
	mkdir -p docs site
	./bin/netconf-audit examples/configs > docs/sample-output.txt; true
	./bin/netconf-audit examples/configs --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "netconf-audit" "Audits Cisco IOS style device configs for weak management plane settings. Tcl." "Synthetic configs for two invented devices."
