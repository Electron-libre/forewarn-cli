# Completes the SBOM cargo-cyclonedx writes of a release binary (ADR 0016), which `forewarn check` then finds complete:
# - the product's manufacturer, and the supplier of each workspace crate, is $manufacturer ($manufacturer_url);
# - each workspace crate gets the SHA-256 of its source tree $hashes names (crate name -> hex digest), none if absent;
# - each crates.io crate gets crates.io as supplier, its distributor; its `authors` stay.
# A component from another source is left as written, so `forewarn check` fails the release on it.
# Every `if` has its `else`: jq before 1.7 requires it.

def manufacturer: {name: $manufacturer, url: [$manufacturer_url]};
def crates_io: {name: "crates.io", url: ["https://crates.io"]};

def complete:
  (.["bom-ref"] // "") as $ref
  | if $ref | startswith("registry+https://github.com/rust-lang/crates.io-index#") then
      .supplier = crates_io
    elif $ref | startswith("path+file://") then
      .supplier = manufacturer
      | if $hashes[.name] then .hashes = [{alg: "SHA-256", content: $hashes[.name]}] else . end
    else . end
  | if .components then .components |= map(complete) else . end;

.metadata.component.manufacturer = manufacturer
| if .components then .components |= map(complete) else . end
