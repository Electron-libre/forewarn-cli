# Completes the SBOM cargo-cyclonedx writes of a release binary (ADR 0016), which `forewarn check` then finds complete:
# - $hashes names each crate of the workspace (package name -> SHA-256 of its source tree): the product and each of
#   these crates get the hash, $manufacturer ($manufacturer_url) as manufacturer of the product and as supplier of
#   the crates;
# - each crates.io crate gets crates.io as supplier, its distributor; its `authors` stay.
# A component from another source, a path crate outside the workspace included, is left as written, so that
# `forewarn check` fails the release on it rather than the manufacturer be named supplier of code it did not write.
# Every `if` has its `else`: jq before 1.7 requires it.

def manufacturer: {name: $manufacturer, url: [$manufacturer_url]};
def crates_io: {name: "crates.io", url: ["https://crates.io"]};
def source_hash: [{alg: "SHA-256", content: $hashes[.name]}];
def of_workspace: ((.["bom-ref"] // "") | startswith("path+file://")) and $hashes[.name] != null;

def complete:
  if (.["bom-ref"] // "") | startswith("registry+https://github.com/rust-lang/crates.io-index#") then
    .supplier = crates_io
  elif of_workspace then
    .supplier = manufacturer | .hashes = source_hash
  else . end
  | if .components then .components |= map(complete) else . end;

.metadata.component |= (.manufacturer = manufacturer | if of_workspace then .hashes = source_hash else . end)
| if .components then .components |= map(complete) else . end
