HOST := baseline
RUN := nix develop .\#ci -c
# The pinned scan tools run as flake packages, so nothing builds the
# default shell (which carries the 3 GB DB on PATH).
GRYPE = nix shell .\#grype -c grype
VEXCTL = nix shell .\#vexctl -c vexctl
SBOMNIX = nix shell .\#sbomnix -c sbomnix
VEXFEED = "$$(nix build --no-link --print-out-paths .\#nixosConfigurations.$(HOST).config.system.build.vexFeed)"

.PHONY: bump carry-forward triage sbom scan zero gate fmt lint test check

# Move every scan pin to its latest version (flake inputs, cpedict, grype DB),
# then regenerate the SBOM and scan: the backlog a bump branch must triage.
bump:
	$(RUN) python3 scripts/bump.py
	$(MAKE) scan

# Carry decided verdicts forward to the versions `make bump` brought in
# (report: reports/carry-forward-<host>.md), then show what is left for a
# human: `make zero` fails until every finding is triaged.
carry-forward:
	$(RUN) python3 scripts/kernel-cna-triage.py $(HOST)
	$(RUN) python3 scripts/carry-forward.py $(HOST) --vex $(VEXFEED) --report reports/carry-forward-$(HOST).md
	$(MAKE) zero

# The triage preview the user signs off (the triage skill): kernel drafts,
# carry-forward without writing, decision records in reports/decisions/
# with their claims checked -> reports/triage-<host>.md. Nothing is written
# to the feed; `make carry-forward`, `kernel-cna-triage.py --apply` and
# `feed.py apply` do that after the sign-off.
triage: scan
	$(RUN) python3 scripts/kernel-cna-triage.py $(HOST)
	$(RUN) python3 scripts/carry-forward.py $(HOST) --vex $(VEXFEED) --dry-run --report reports/carry-forward-$(HOST).md
	$(RUN) python3 scripts/triage-report.py $(HOST) --vex $(VEXFEED)

# Regenerate the reference system's SBOM (CycloneDX), building it if required.
# The SBOM records its target closure (metadata.component nix:output_path) and
# the sbomnix version, which names the pinned CPE dictionary. Therefore eval tells
# us whether it is already current, and the expensive sbomnix run is skipped
# when neither the closure nor the generator changed.
sbom:
	@mkdir -p sboms
	@current="$$(nix eval --raw .#nixosConfigurations.$(HOST).config.system.build.toplevel) $$(nix eval --raw .#sbomnix.version)"; \
	recorded="$$($(RUN) jq -r '[(.metadata.component.properties[]? | select(.name == "nix:output_path").value), (.metadata.tools[]? | select(.name == "sbomnix").version)] | join(" ")' sboms/$(HOST).cdx.json 2>/dev/null || true)"; \
	if [ "$$current" = "$$recorded" ]; then \
		echo "sbom $(HOST): unchanged ($$current)"; \
	else \
		$(SBOMNIX) .#nixosConfigurations.$(HOST).config.system.build.toplevel --cdx sboms/$(HOST).cdx.json --csv sboms/$(HOST).csv --spdx sboms/$(HOST).spdx.json; \
	fi

# Scan the SBOM with the pinned grype and grype DB (tools/default.nix)
scan: sbom
	@mkdir -p reports
	$(GRYPE) sbom:sboms/$(HOST).cdx.json \
		--vex $(VEXFEED) \
		-o table -o json=reports/$(HOST).vulns.json

# Exit non-zero on any untriaged finding.
zero: scan
	$(RUN) python3 scripts/zero.py $(HOST) --vex $(VEXFEED)

# The zero gate, as CI runs it on every pull request. It regenerates the SBOM,
# checks that the committed one is identical apart from serialNumber and
# timestamp (scripts/sbom-check.py), and scans the regenerated one; zero
# untriaged findings are required.
gate:
	@mkdir -p reports
	$(SBOMNIX) .#nixosConfigurations.$(HOST).config.system.build.toplevel --cdx reports/regenerated-$(HOST).cdx.json --csv reports/regenerated-$(HOST).csv --spdx reports/regenerated-$(HOST).spdx.json
	$(RUN) python3 scripts/sbom-check.py sboms/$(HOST).cdx.json reports/regenerated-$(HOST).cdx.json
	$(GRYPE) sbom:reports/regenerated-$(HOST).cdx.json \
		--vex $(VEXFEED) \
		-o table -o json=reports/$(HOST).vulns.json
	$(RUN) python3 scripts/zero.py $(HOST) --vex $(VEXFEED)

fmt:
	nix fmt
	$(RUN) ruff format

lint:
	$(RUN) statix check .
	$(RUN) deadnix --fail --exclude hosts/baseline/configuration.nix .
	$(RUN) basedpyright
	$(RUN) ruff check
	$(RUN) ruff format --check
	$(VEXCTL) validate --strict vex/baseline.openvex.json $(VEXFEED)

test:
	nix flake check

check: fmt lint test
