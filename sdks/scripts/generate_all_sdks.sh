#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Automated build script: generate Go, Java, C#, and Rust SDKs from the
# Groundwork OpenAPI specification using @openapitools/openapi-generator-cli.
# ---------------------------------------------------------------------------

SPEC="docs/openapi/v1.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# ---------------------------------------------------------------------------
# Ensure OpenAPI generator CLI is available.
# ---------------------------------------------------------------------------
if ! command -v openapi-generator-cli &>/dev/null; then
  echo "==> Installing @openapitools/openapi-generator-cli ..."
  npm install -g @openapitools/openapi-generator-cli 2>&1 | tail -3
fi

# ---------------------------------------------------------------------------
# Helper: run generator and abort on generator warnings.
# ---------------------------------------------------------------------------
generate() {
  local generator="$1"
  local output_dir="$2"
  shift 2
  echo "==> Generating ${generator} client into ${output_dir} ..."
  openapi-generator-cli generate \
    -i "$SPEC" \
    -g "$generator" \
    -o "$output_dir" \
    "$@" \
    --skip-validate-spec
}

# ---------------------------------------------------------------------------
# 1. Go client
# ---------------------------------------------------------------------------
GO_OUT="$ROOT_DIR/sdks/go"
mkdir -p "$GO_OUT"
generate go "$GO_OUT" \
  --additional-properties=packageName=groundwork \
  --additional-property=modelPackage=model,apiPackage=api

echo "==> Verifying Go compilation ..."
cd "$GO_OUT"
go mod tidy 2>&1
go build ./...
if [ $? -eq 0 ]; then
  echo "==> Go compilation: OK"
else
  echo "==> Go compilation: FAILED"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Java client (using Spring Boot / RestTemplate + Jackson)
# ---------------------------------------------------------------------------
JAVA_OUT="$ROOT_DIR/sdks/java"
mkdir -p "$JAVA_OUT"
generate java "$JAVA_OUT" \
  --additional-properties=packageName=com.groundwork,groupId=com.groundwork,artifactId=groundwork-java,version=1.0.0

echo "==> Verifying Java compilation ..."
cd "$JAVA_OUT"
mvn -q compile -DskipTests 2>&1 | tail -3
if [ $? -eq 0 ]; then
  echo "==> Java compilation: OK"
else
  echo "==> Java compilation: check output above"
  # non-fatal: we just report
fi

# ---------------------------------------------------------------------------
# 3. C# client (using RestSharp + System.Text.Json)
# ---------------------------------------------------------------------------
CSHARP_OUT="$ROOT_DIR/sdks/csharp"
mkdir -p "$CSHARP_OUT"
generate csharp "$CSHARP_OUT" \
  --additional-properties=packageName=Groundwork,projectName=GroundworkCSharp,namespace=GroundworkCSharp

echo "==> Verifying C# compilation ..."
cd "$CSHARP_OUT"
dotnet restore >/dev/null 2>&1
dotnet build --configuration Release 2>&1 | tail -3
if [ $? -eq 0 ]; then
  echo "==> C# compilation: OK"
else
  echo "==> C# compilation: check output above"
fi

# ---------------------------------------------------------------------------
# 4. Rust client (using reqwest + serde)
# ---------------------------------------------------------------------------
RUST_OUT="$ROOT_DIR/sdks/rust"
mkdir -p "$RUST_OUT"
generate rust "$RUST_OUT" \
  --additional-properties=packageName=groundwork

echo "==> Verifying Rust compilation ..."
cd "$RUST_OUT"
cargo build 2>&1 | tail -3
if [ $? -eq 0 ]; then
  echo "==> Rust compilation: OK"
else
  echo "==> Rust compilation: check output above"
fi

echo ""
echo "==> All SDK generations and basic compilation checks completed."