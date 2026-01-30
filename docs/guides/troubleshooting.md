# Troubleshooting

Quick fixes for common issues. Use `--log-level debug` on any command for verbose output.

## Network & OSV Issues

### "No vulnerabilities found" (unexpected)

1. **Check network access**: Deputy queries `api.osv.dev` for vulnerability data.
2. **Verify inventory detection**: Run `deputy list` to confirm packages are being discovered.
3. **Check ecosystem coverage**: OSV coverage varies by ecosystem; some packages may not have data yet.

```console
# Debug mode shows OSV query details
$ deputy scan --log-level debug
```

### OSV timeouts or failures

- Deputy continues with warnings when OSV is unreachable (SBOM generation still works).

## Git & Repository Issues

### "could not resolve ref" errors

```console
# Wrong: shell expands @{...}
$ deputy diff HEAD@{yesterday} HEAD

# Right: quote time-based refs
$ deputy diff "HEAD@{yesterday}" HEAD
```

### "no dependencies found" in a valid repo

- Ensure you're in a directory with manifest files (`go.mod`, `package.json`, etc.).
- Check `--ref`: scanning a ref without manifest files yields empty results.
- Try `deputy list --show-sources` to see which files Deputy detects.

### Working tree vs committed state

```console
# Scan committed state (HEAD)
$ deputy scan

# Include uncommitted changes
$ deputy scan --ref WORKING
```

## Policy Issues

### Policy not evaluating as expected

1. **Lint first**: `deputy policy lint policy/*.yaml`
2. **Test in isolation**: `deputy policy eval --policy policy.yaml --input test.json`
3. **Check entrypoints**: Ensure the policy targets the right entrypoint (`scan_vulnerability` vs `scan_report`).
4. **Enable tracing**: Use `--policy-trace` (when available) to see evaluation steps.

### CEL expression errors

Common mistakes:
- Missing optional handling for external data: use `vulnerability.?fixedVersions.orValue([])` for fields that may not exist
- Note: `pkg` fields have defaults, so `pkg.licenses`, `pkg.version`, etc. work without `?.orValue()`
- Wrong type comparisons: severity is a string (`"HIGH"`), not an enum
- List vs single value: `vulnerabilities` is a list; use `.exists()` or `.filter()`

## Proxy Issues

### Unexpected blocks

Start with advisory mode to observe without blocking:

```yaml
policies:
  - name: my-policy
    mode: advisory  # logs warnings, doesn't block
```

Then:
1. Check logs for the policy/reason that triggered
2. Validate with `deputy policy lint` / `deputy policy test`
3. Use `deputy proxy inspect --url <url>` to test specific requests

### Proxy not intercepting requests

Verify environment variables are set correctly:
- Go: `GOPROXY=http://localhost:8080`
- npm: `npm_config_registry=http://localhost:8081`
- PyPI: `PIP_INDEX_URL=http://localhost:8082/simple`

## Authentication & Credentials

Deputy uses standard credential chains for cloud providers and container registries. Most authentication issues can be diagnosed by understanding which credential source is being used.

### CLI Error Messages

**Deputy provides detailed, registry-specific error messages** with actionable remediation steps. When you encounter an authentication error, read the full message carefully - it typically includes:

- The exact problem (authentication, not found, rate limit)
- Multiple solution options appropriate for your registry
- Required permissions or scopes
- Links to create tokens or configure credentials

Example ECR error output:
```
ECR authentication failed for 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest

Ensure AWS credentials are configured:

  Option 1: Use environment variables
    export AWS_ACCESS_KEY_ID=<your-access-key>
    export AWS_SECRET_ACCESS_KEY=<your-secret-key>
    export AWS_REGION=us-east-1

  Option 2: Use AWS CLI to configure credentials
    aws configure

  Option 3: Use docker credential helper
    Install: https://github.com/awslabs/amazon-ecr-credential-helper
    Then run: aws ecr get-login-password --region us-east-1 | \
      docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
```

**Tip:** The CLI detects your specific registry type (ECR, GHCR, GCR, ACR, Docker Hub) and tailors the guidance accordingly. If you're seeing generic errors, ensure you're using the latest version of Deputy.

### Credential Resolution Order

Deputy resolves credentials in a layered manner, checking multiple sources in order:

**Container Registries:**
1. Docker config (`~/.docker/config.json`) and credential helpers
2. Environment variables (registry-specific)
3. Anonymous access (if allowed by registry)

**AWS (for cloud resources and ECR):**
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. Shared config file (`~/.aws/config`) with `AWS_SDK_LOAD_CONFIG=true`
4. IAM role for EC2 (instance metadata)
5. IAM role for ECS (container credentials)
6. Web Identity Token (EKS IRSA)

### Container Registry Authentication

#### Amazon ECR

**Error:**
```
Error: GET https://123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/.../manifests/latest: UNAUTHORIZED
```

**Solutions (in order of preference):**

1. **Use AWS credentials directly** (Deputy handles ECR token exchange automatically):
   ```console
   # Environment variables
   $ export AWS_ACCESS_KEY_ID=AKIA...
   $ export AWS_SECRET_ACCESS_KEY=...
   $ export AWS_REGION=us-east-1
   $ deputy scan 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest
   ```

2. **Use AWS CLI profile**:
   ```console
   $ export AWS_PROFILE=my-profile
   $ deputy scan 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest
   ```

3. **Use docker login** (traditional approach, credentials cached for 12 hours):
   ```console
   $ aws ecr get-login-password --region us-east-1 | \
       docker login --username AWS --password-stdin \
       123456789012.dkr.ecr.us-east-1.amazonaws.com
   $ deputy scan 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest
   ```

4. **For CI/CD (GitHub Actions with OIDC)**:
   ```yaml
   - uses: aws-actions/configure-aws-credentials@v4
     with:
       role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
       aws-region: us-east-1
   - run: deputy scan ${{ env.ECR_REGISTRY }}/app:${{ github.sha }}
   ```

**Required IAM permissions for ECR:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer"
    ],
    "Resource": "*"
  }]
}
```

#### GitHub Container Registry (GHCR)

**Error:**
```
Error: GET https://ghcr.io/v2/.../manifests/latest: UNAUTHORIZED
```

**Solutions:**

1. **Use GITHUB_TOKEN environment variable**:
   ```console
   $ export GITHUB_TOKEN=ghp_...
   $ deputy scan ghcr.io/owner/app:v1.0.0
   ```

2. **Use docker login**:
   ```console
   $ echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
   $ deputy scan ghcr.io/owner/app:v1.0.0
   ```

**Token requirements:**
- Fine-grained PAT: `read:packages` permission on the repository
- Classic PAT: `read:packages` scope
- GitHub Actions: `${{ secrets.GITHUB_TOKEN }}` works automatically for same-repo images

#### Google Container Registry (GCR) / Artifact Registry

**Error:**
```
Error: GET https://gcr.io/v2/.../manifests/latest: UNAUTHORIZED
```

**Solutions:**

1. **Use gcloud CLI**:
   ```console
   $ gcloud auth configure-docker
   $ deputy scan gcr.io/project/image:tag
   ```

2. **For Artifact Registry**:
   ```console
   $ gcloud auth configure-docker us-docker.pkg.dev
   $ deputy scan us-docker.pkg.dev/project/repo/image:tag
   ```

3. **Use service account key**:
   ```console
   $ export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
   $ deputy scan gcr.io/project/image:tag
   ```

4. **Use docker login with service account**:
   ```console
   $ cat key.json | docker login -u _json_key --password-stdin https://gcr.io
   ```

#### Azure Container Registry (ACR)

**Error:**
```
Error: GET https://myregistry.azurecr.io/v2/.../manifests/latest: UNAUTHORIZED
```

**Solutions:**

1. **Use Azure CLI**:
   ```console
   $ az acr login --name myregistry
   $ deputy scan myregistry.azurecr.io/image:tag
   ```

2. **Use service principal**:
   ```console
   $ docker login myregistry.azurecr.io -u $SP_APP_ID -p $SP_PASSWORD
   ```

#### Docker Hub

**Error:**
```
Error: toomanyrequests: You have reached your pull rate limit
```

**Solutions:**

1. **Authenticate to increase limits**:
   ```console
   $ docker login
   $ deputy scan nginx:1.25
   ```
   - Anonymous: 100 pulls/6 hours
   - Authenticated: 200 pulls/6 hours
   - Paid plans: Higher limits

2. **Use local Docker daemon** (avoids rate limits):
   ```console
   $ docker pull nginx:1.25
   $ deputy scan docker-daemon://nginx:1.25
   ```

### AWS Cloud Resource Authentication

For scanning AWS resources like AMIs and EBS snapshots:

**Error:**
```
Error: operation error EC2: DescribeImages, failed to sign request: failed to retrieve credentials
```

**Solutions:**

1. **Environment variables**:
   ```console
   $ export AWS_ACCESS_KEY_ID=AKIA...
   $ export AWS_SECRET_ACCESS_KEY=...
   $ export AWS_REGION=us-east-1
   $ deputy scan aws://ami/ami-0123456789abcdef0
   ```

2. **Named profile**:
   ```console
   $ deputy scan aws://ami/ami-0123456789abcdef0 --profile production
   ```

3. **EC2 instance role** (automatic when running on EC2):
   ```console
   # No explicit credentials needed - uses instance metadata
   $ deputy scan aws://ami/ami-0123456789abcdef0
   ```

4. **EKS with IRSA** (automatic with properly configured service account):
   ```yaml
   # Kubernetes service account with IAM role annotation
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     annotations:
       eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/DeputyRole
   ```

**Required IAM permissions for AMI/EBS scanning:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeImages",
      "ec2:DescribeSnapshots",
      "ebs:ListSnapshotBlocks",
      "ebs:GetSnapshotBlock"
    ],
    "Resource": "*"
  }]
}
```

### Debugging Credential Issues

**Enable debug logging to see credential resolution:**
```console
$ deputy scan --log-level debug ghcr.io/owner/app:v1
```

**Check Docker credential helpers:**
```console
$ cat ~/.docker/config.json
{
  "credHelpers": {
    "gcr.io": "gcloud",
    "us.gcr.io": "gcloud",
    "123456789012.dkr.ecr.us-east-1.amazonaws.com": "ecr-login"
  }
}
```

**Verify AWS credentials:**
```console
$ aws sts get-caller-identity
{
    "UserId": "AIDAEXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/developer"
}
```

**Test ECR authentication manually:**
```console
$ aws ecr get-authorization-token --region us-east-1
```

### Common Authentication Mistakes

1. **Wrong region for ECR**: The region in the URL must match your AWS config
   ```console
   # Wrong: configured for us-west-2 but accessing us-east-1
   $ export AWS_REGION=us-west-2
   $ deputy scan 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest

   # Right: region matches
   $ export AWS_REGION=us-east-1
   $ deputy scan 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest
   ```

2. **Expired credentials**: ECR tokens from `docker login` expire after 12 hours
   ```console
   # Re-authenticate
   $ aws ecr get-login-password | docker login --username AWS --password-stdin ...
   ```

3. **Missing cross-account permissions**: Accessing ECR in a different account requires explicit permissions

4. **GITHUB_TOKEN scope insufficient**: Ensure the token has `read:packages` permission

### Cloud Provider Plugin Authentication

Deputy supports external cloud provider plugins (`deputy-cloud-*`) for scanning resources from platforms like OpenStack, vSphere, and custom cloud environments. Plugin authentication uses each platform's standard credential chain.

#### Plugin Discovery Issues

**Error:**
```
no cloud plugin found for target: mycloud://instance/i-123
```

**Solutions:**

1. **Verify plugin installation**: Plugins must be named `deputy-cloud-<name>` and be in PATH
   ```console
   # Check if plugin is discoverable
   $ which deputy-cloud-mycloud
   /usr/local/bin/deputy-cloud-mycloud

   # List discovered plugins (if supported)
   $ deputy list --plugins
   ```

2. **Verify plugin is executable**:
   ```console
   $ ls -la $(which deputy-cloud-mycloud)
   -rwxr-xr-x 1 user user ... deputy-cloud-mycloud
   ```

3. **Test plugin directly**:
   ```console
   # Start plugin manually to check for errors
   $ deputy-cloud-mycloud --socket /tmp/test.sock
   ```

#### OpenStack Plugin

**Error:**
```
authentication failed for openstack: Unauthorized
```

**Solutions:**

1. **Use environment variables** (OpenStack RC file):
   ```console
   $ source openstack-rc.sh
   # Or set manually:
   $ export OS_AUTH_URL=https://identity.example.com:5000/v3
   $ export OS_PROJECT_NAME=my-project
   $ export OS_USERNAME=my-user
   $ export OS_PASSWORD=my-password
   $ export OS_REGION_NAME=RegionOne
   $ deputy scan openstack://instance/xxx
   ```

2. **Use clouds.yaml**:
   ```yaml
   # ~/.config/openstack/clouds.yaml
   clouds:
     mycloud:
       auth:
         auth_url: https://identity.example.com:5000/v3
         project_name: my-project
         username: my-user
         password: my-password
       region_name: RegionOne
   ```
   ```console
   $ export OS_CLOUD=mycloud
   $ deputy scan openstack://instance/xxx
   ```

3. **Use application credentials** (recommended for automation):
   ```console
   $ export OS_AUTH_TYPE=v3applicationcredential
   $ export OS_APPLICATION_CREDENTIAL_ID=xxx
   $ export OS_APPLICATION_CREDENTIAL_SECRET=yyy
   ```

#### vSphere Plugin

**Error:**
```
authentication failed for vsphere: Login failure
```

**Solutions:**

1. **Use environment variables**:
   ```console
   $ export VSPHERE_SERVER=vcenter.example.com
   $ export VSPHERE_USER=administrator@vsphere.local
   $ export VSPHERE_PASSWORD=my-password
   $ export VSPHERE_ALLOW_UNVERIFIED_SSL=true  # For self-signed certs
   $ deputy scan vsphere://vm/vm-123
   ```

2. **Verify connectivity**:
   ```console
   $ curl -k https://vcenter.example.com/sdk
   ```

#### Plugin Communication Failures

**Error:**
```
cloud plugin "mycloud" socket not ready: timeout waiting for socket
```

**Solutions:**

1. **Check plugin logs**: Plugins log to stderr during startup
   ```console
   $ deputy scan --log-level debug mycloud://...
   ```

2. **Increase timeout** (if plugin takes longer to initialize):
   ```console
   # Some plugins support timeout configuration
   $ export DEPUTY_PLUGIN_TIMEOUT=30s
   ```

3. **Check for port conflicts**: Plugins use Unix sockets in temp directories
   ```console
   $ ls -la /tmp/deputy-cloud-*
   ```

#### General Plugin Debugging

Enable debug logging to see plugin communication:
```console
$ deputy scan --log-level debug mycloud://instance/i-123
```

This shows:
- Plugin discovery and selection
- RPC calls between Deputy and the plugin
- Progress events during resource materialization
- Any errors returned by the plugin

## Rate Limits

### GitHub rate limits during enrichment

Set a token to increase limits:

```console
$ export GITHUB_TOKEN=ghp_...
$ deputy sbom --enrich-licenses
```

### deps.dev enrichment failures

- deps.dev has its own rate limits; batch operations may hit them.
- Use `--license-source scan` for local-only license detection.

### Container registry rate limits

See the Docker Hub section above for authentication to increase limits.

## Performance Issues

### Slow scans on large repositories

- Use `--ecosystems go,npm` to limit scanning to specific ecosystems.
- For repeated scans, the proxy caches OSV results automatically.
- Consider generating an SBOM once and scanning that: `deputy sbom | deputy scan sbom -`

## OpenTelemetry Observability

Deputy supports OpenTelemetry for distributed tracing, metrics, and log correlation. This is useful for diagnosing performance issues and understanding request flows.

```bash
# Enable OTel with a local collector
export DEPUTY_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_EXPORTER_OTLP_INSECURE=true

deputy scan
```

See the [Observability Guide](observability.md) for full setup instructions and a Docker Compose stack for local development.

## Getting Help

If these don't resolve your issue:

1. Run with `--log-level debug` and check the output
2. Enable OTel tracing to diagnose performance issues
3. Check [GitHub Issues](https://github.com/picatz/deputy/issues) for similar reports
4. Open a new issue with debug logs and reproduction steps
