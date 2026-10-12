# PoC: untrusted gateway catalog selects which tinfoilsh/* code a NewGateway client trusts

All data under `public/` was downloaded from api.github.com / github.com release assets
(public metadata only; no Tinfoil production host was contacted).

Repro (work copy of tinfoil-go at HEAD ef79d8e, Go 1.27.1):

    source /root/tinfoil-review/env.sh
    cd /root/tinfoil-review/work/go-verifier-provenance/tinfoil-go
    # A: dev-box releases pass code provenance + freshness for their catalog-named repo
    go test ./verify/internal/provenance/ -run TestPoC_DevBoxReleasesPassCodeProvenanceAndFreshness -v -count=1
    # B: loopback HTTPS gateway serving a catalog that maps llama3-3-70b -> tinfoilsh/confidential-ubuntu-tinfoil-config
    go test . -run TestPoC_GatewayCatalogSelectsDevBoxRepo -v -count=1
    # C: the whole reference-values layer of VerifyV3 (code + platform + both witnesses) accepts the dev-box release
    go test ./verify/ -run TestPoC_ReferenceValuesAcceptDevBoxRelease -v -count=1

Logs: testA-provenance.log, testB-catalog.log, testC-reference-values.log
Test sources: tinfoil-go/verify/internal/provenance/poc_devbox_provenance_test.go,
              tinfoil-go/poc_catalog_test.go, tinfoil-go/verify/poc_reference_values_test.go
Public artifacts: public/<repo>/<tag>/{tinfoil-deployment.json,code-bundle.json,freshness-bundle.json,leaf.der,measured-config.yml}
                  public/platform-endorsements/v0.0.17/{platform-endorsements.json,platform-bundle.json,freshness-bundle.json}
