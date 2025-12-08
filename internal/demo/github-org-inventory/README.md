# Run

```console
$ time GITHUB_TOKEN=$(gh auth token) go run main.go --org temporalio --license-scan
...
time=2025-12-08T16:11:46.106-05:00 level=INFO msg="wrote 7 ecosystem CSVs to inventory-output/temporalio"
GITHUB_TOKEN=$(gh auth token) go run main.go --org temporalio --license-scan  78.73s user 50.68s system 69% cpu 3:05.61 total
```

## Tests and Strict Validation Harness

```console
$  time GITHUB_TOKEN=$(gh auth token) STRICT_LICENSE_CHECK=1 go test -v
...          
=== RUN   TestCollectRowsFromPackages
=== PAUSE TestCollectRowsFromPackages
=== RUN   TestInventoryFromWorkspace
=== PAUSE TestInventoryFromWorkspace
=== RUN   TestInventoryOutput_NoUnknowns
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/go.csv
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/java.csv
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/javascript.csv
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/php.csv
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/python.csv
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/ruby.csv
=== RUN   TestInventoryOutput_NoUnknowns/temporalio/rust.csv
=== NAME  TestInventoryOutput_NoUnknowns
    output_validation_test.go:55: validation failures (sample):
        inventory-output/temporalio/go.csv:2: missing license for github.com/Azure/azure-sdk-for-go/sdk/azcore@1.19.1
        inventory-output/temporalio/go.csv:3: missing license for github.com/Azure/azure-sdk-for-go/sdk/azidentity@1.13.0
        inventory-output/temporalio/go.csv:4: missing license for github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache@0.3.2
        inventory-output/temporalio/go.csv:5: missing license for github.com/Azure/azure-sdk-for-go/sdk/internal@1.11.2
        inventory-output/temporalio/go.csv:6: missing license for github.com/AzureAD/microsoft-authentication-extensions-for-go/cache@0.1.1
        inventory-output/temporalio/go.csv:9: missing license for github.com/aws/aws-sdk-go-v2/config@1.29.17
        inventory-output/temporalio/go.csv:10: missing license for github.com/aws/aws-sdk-go-v2/credentials@1.17.70
        inventory-output/temporalio/go.csv:11: missing license for github.com/aws/aws-sdk-go-v2/feature/ec2/imds@1.16.32
        inventory-output/temporalio/go.csv:12: missing license for github.com/aws/aws-sdk-go-v2/internal/configsources@1.3.36
        inventory-output/temporalio/go.csv:13: missing license for github.com/aws/aws-sdk-go-v2/internal/endpoints/v2@2.6.36
        inventory-output/temporalio/go.csv:14: missing license for github.com/aws/aws-sdk-go-v2/internal/ini@1.8.3
        inventory-output/temporalio/go.csv:15: missing license for github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding@1.12.4
        inventory-output/temporalio/go.csv:16: missing license for github.com/aws/aws-sdk-go-v2/service/internal/presigned-url@1.12.17
        inventory-output/temporalio/go.csv:17: missing license for github.com/aws/aws-sdk-go-v2/service/sso@1.25.5
        inventory-output/temporalio/go.csv:47: missing license for github.com/temporalio/access@(devel)
        inventory-output/temporalio/go.csv:49: missing license for go@1.25.4
        inventory-output/temporalio/go.csv:51: missing license for golang.org/x/crypto@0.45.0
        inventory-output/temporalio/go.csv:52: missing license for golang.org/x/net@0.47.0
        inventory-output/temporalio/go.csv:53: missing license for golang.org/x/oauth2@0.30.0
        inventory-output/temporalio/go.csv:54: missing license for golang.org/x/sys@0.38.0
--- FAIL: TestInventoryOutput_NoUnknowns (0.01s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/go.csv (0.00s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/java.csv (0.00s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/javascript.csv (0.01s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/php.csv (0.00s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/python.csv (0.00s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/ruby.csv (0.00s)
    --- PASS: TestInventoryOutput_NoUnknowns/temporalio/rust.csv (0.00s)
=== CONT  TestCollectRowsFromPackages
=== CONT  TestInventoryFromWorkspace
time=2025-12-08T16:15:13.613-05:00 level=INFO msg="package rows collected" repo=demo-repo packages=3 ecosystems=2 missing_license_rows=0
--- PASS: TestCollectRowsFromPackages (0.00s)
2025/12/08 16:15:13 Starting filesystem walk for root: /var/folders/ty/psc8zc4961s9jr3k6fhhztdr0000gn/T/TestInventoryFromWorkspace4264359535/001
2025/12/08 16:15:13 End status: 1 dirs visited, 4 inodes visited, 1 Extract calls, 224.792µs elapsed, 225µs wall time
time=2025-12-08T16:15:13.614-05:00 level=INFO msg="inventory scan finished" repo=demo-repo packages=2 elapsed_ms=0
time=2025-12-08T16:15:13.614-05:00 level=INFO msg="package rows collected" repo=demo-repo packages=2 ecosystems=1 missing_license_rows=0
--- PASS: TestInventoryFromWorkspace (0.00s)
FAIL
exit status 1
FAIL    github.com/picatz/deputy/internal/demo/github-org-inventory     0.373s
GITHUB_TOKEN=$(gh auth token) STRICT_LICENSE_CHECK=1 go test -v  1.13s user 1.97s system 112% cpu 2.766 total
```