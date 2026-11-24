# frozen_string_literal: true

scope 'v2/virtual_registries/container/:id', format: false do
  constraints(
    path: %r{
      #{::Gitlab::PathRegex.container_image_regex.source}/                 # image name with trailing slash
      (?:manifests/#{::Gitlab::PathRegex.oci_tag_or_digest_regex.source} | # manifests/tag_or_digest
      blobs/#{::Gitlab::PathRegex.oci_blob_digest_regex.source})           # OR blobs/sha
    }x
  ) do
    controller 'virtual_registries/container' do
      get '*path', action: :show
      post '*path/upload', action: :upload
    end
  end

  constraints(
    path: %r{
      #{::Gitlab::PathRegex.container_image_regex.source}/                 # image name with trailing slash
      referrers/#{::Gitlab::PathRegex.oci_blob_digest_regex.source}        # referrers/sha
    }x
  ) do
    controller 'virtual_registries/container' do
      get '*path', action: :referrers
    end
  end

  # Catch-all for malformed referrers paths (e.g. invalid digest format).
  # Must come after the strict referrers constraint so well-formed requests are unaffected.
  # Returns an OCI-compliant 400 rather than falling through to unrelated routes.
  controller 'virtual_registries/container' do
    get '*image/referrers/*tag', action: :referrers_not_found
  end
end
