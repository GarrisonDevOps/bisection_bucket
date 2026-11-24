# frozen_string_literal: true

require 'tempfile'

module Geo
  class ContainerRepositorySync
    include Gitlab::Utils::StrongMemoize
    include ::Gitlab::Geo::LogHelpers

    FOREIGN_MEDIA_TYPE = 'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip'

    # Manifests that reference other manifests (fat manifests)
    LIST_MANIFESTS = [
      ContainerRegistry::Client::DOCKER_DISTRIBUTION_MANIFEST_LIST_V2_TYPE,
      ContainerRegistry::Client::OCI_DISTRIBUTION_INDEX_TYPE
    ].freeze

    # Cosign / Sigstore signature tags follow the OCI 1.1 referrers tag-name
    # convention: sha256-<image-digest>, optionally suffixed with .sig/.att/.sbom.
    COSIGN_TAG_PATTERN = /\Asha256-[0-9a-f]{64}(?:\.(?:sig|att|sbom))?\z/

    # Upper bound on how deep a chain of subject references is followed, to
    # guard against pathological or cyclic referrer graphs.
    MAX_SUBJECT_DEPTH = 5

    attr_reader :repository_path, :container_repository

    def initialize(container_repository)
      @container_repository = container_repository
      @repository_path = container_repository.path
    end

    def execute
      raise "No valid connection to primary registry" unless client.connected?

      tags_to_sync.each do |tag|
        sync_tag(tag)
      rescue StandardError => e
        log_error "Error while syncing tag #{tag[:name]}: #{e.message}"
      end

      remove_tags(tags_to_remove.map { |tag| tag.fetch(:name) })

      true
    end

    private

    def sync_tag(tag)
      manifest = client.repository_raw_manifest(repository_path, tag[:name])
      manifest_parsed = Gitlab::Json.safe_parse(manifest)

      # OCI 1.1 referrers (cosign signatures, attestations, SBOMs) reference a
      # subject manifest - the signed image - via the `subject` field or the
      # `sha256-<digest>` tag-name convention. The subject must already exist on
      # the secondary, otherwise the registry rejects the push with
      # MANIFEST_BLOB_UNKNOWN. Sync it (and its dependencies) first.
      ensure_subject_present(tag[:name], manifest_parsed)

      sync_manifest_contents(manifest_parsed)

      container_repository.push_manifest(tag[:name], manifest, resolve_media_type(manifest_parsed))
    end

    # Syncs the contents a manifest references: the submanifests of an OCI index
    # / fat manifest, or its blobs otherwise. Buildkit cache indexes are
    # oci-spec-invalid and reference blobs directly, so they take the blob path
    # too; an index that omits `manifests` is treated as having no submanifests.
    def sync_manifest_contents(manifest_parsed)
      submanifests = manifest_parsed['manifests']

      if LIST_MANIFESTS.include?(manifest_parsed['mediaType']) &&
          submanifests.present? &&
          !buildkit_oci_incompatible_index?(submanifests)
        push_index_submanifests(submanifests)
      else
        sync_manifest_blobs(manifest_parsed)
      end
    end

    # Resolves the Content-Type for a manifest push. The body mediaType is
    # optional per the OCI spec (buildkit often omits it), so fall back to the
    # descriptor's mediaType from the parent index, then to the OCI image
    # manifest type, so the value sent to the registry is never nil.
    def resolve_media_type(manifest_parsed, descriptor_media_type = nil)
      manifest_parsed['mediaType'] || descriptor_media_type || ContainerRegistry::Client::OCI_MANIFEST_V1_TYPE
    end

    # Pushes each submanifest of a fat manifest / OCI image index to the
    # secondary. Submanifests must exist before the index that references them.
    #
    # Unlike the optional subject fetch, a 404 here is deliberately left to
    # raise and retry: the index references these submanifests, so it cannot be
    # validly pushed without them. Swallowing the error would only move the
    # failure to the index push, so failing fast and retrying is correct.
    def push_index_submanifests(submanifest_refs)
      submanifest_refs.each do |submanifest_ref|
        submanifest_raw = client.repository_raw_manifest(repository_path, submanifest_ref['digest'])
        submanifest_parsed = Gitlab::Json.safe_parse(submanifest_raw)
        sync_manifest_blobs(submanifest_parsed)

        container_repository.push_manifest(
          submanifest_ref['digest'],
          submanifest_raw,
          resolve_media_type(submanifest_parsed, submanifest_ref['mediaType'])
        )
      end
    end

    # Ensures the OCI 1.1 subject referenced by a manifest exists on the secondary.
    def ensure_subject_present(reference, manifest_parsed)
      digest = subject_digest(reference, manifest_parsed)
      return unless digest

      sync_subject_manifest(digest, 1)
    end

    # Derives the subject (signed image) digest a referrer manifest points to.
    # The explicit `subject` field is authoritative; the `sha256-<digest>` tag
    # name is the fallback convention used by tools that omit the field.
    def subject_digest(reference, manifest_parsed)
      if manifest_parsed.is_a?(Hash) && manifest_parsed['subject'].is_a?(Hash)
        digest = manifest_parsed.dig('subject', 'digest')
        # Always return inside this branch: a present `subject` field is
        # authoritative, so we must not fall through to the cosign tag-name
        # fallback below even when the digest is missing or malformed. The
        # explicit `: nil` (rather than a trailing `if`) is what guarantees
        # that short-circuit.
        return digest.is_a?(String) ? digest.presence : nil
      end

      return unless reference.to_s.match?(COSIGN_TAG_PATTERN)

      "sha256:#{reference[/\Asha256-([0-9a-f]{64})/, 1]}"
    end

    # Recursively ensures a subject manifest (referenced by digest) and all of
    # its own dependencies - a nested subject, index submanifests, and blobs -
    # exist on the secondary, then pushes it. No-op when it is already present,
    # which keeps the operation idempotent and short-circuits referrer chains.
    def sync_subject_manifest(digest, depth)
      if depth > MAX_SUBJECT_DEPTH
        log_error("Subject manifest chain exceeded max depth for #{digest}")
        return
      end

      return if container_repository.manifest_exists?(digest)

      manifest = fetch_subject_manifest(digest)
      return unless manifest

      manifest_parsed = Gitlab::Json.safe_parse(manifest)
      return unless manifest_parsed.is_a?(Hash)

      nested_subject = subject_digest(digest, manifest_parsed)
      sync_subject_manifest(nested_subject, depth + 1) if nested_subject

      sync_manifest_contents(manifest_parsed)

      container_repository.push_manifest(digest, manifest, resolve_media_type(manifest_parsed))
    end

    # Fetches a subject manifest from the primary. The subject may be absent
    # there - an orphan signature whose signed image was deleted and GC'd, or a
    # tag that merely matches the cosign `sha256-<digest>` naming convention.
    # Returns nil on a not-found so the caller falls through and pushes the
    # referrer itself; other fetch errors still propagate to the per-tag rescue.
    #
    # Known limitation: a referrer that carries an explicit `subject` field
    # whose image was GC'd off the primary will still be pushed here, and if the
    # registry validates the subject descriptor on push it rejects it, leaving
    # the tag to retry each run. That is an inherently broken artifact; the
    # common orphan cases above carry no `subject` field and push cleanly.
    def fetch_subject_manifest(digest)
      client.repository_raw_manifest(repository_path, digest)
    rescue EE::ContainerRegistry::Client::NotFoundError
      log_info("Subject manifest not found on primary; skipping subject sync", digest: digest)
      nil
    end

    # Buildkit-cache images have special oci-spec-invalid structure where fat manifests reference
    # blobs directly. Normal OCI fat manifest only references other manifests
    # Issue https://github.com/moby/buildkit/issues/2251
    def buildkit_oci_incompatible_index?(manifests)
      manifests.any? do |manifest|
        manifest['mediaType'].include?('application/vnd.buildkit.cacheconfig')
      end
    end

    def sync_manifest_blobs(manifest)
      list_blobs(manifest).each do |digest|
        sync_blob(digest)
      end
    end

    def sync_blob(digest)
      return if container_repository.blob_exists?(digest)

      blob_io, size = client.pull_blob(repository_path, digest)
      container_repository.push_blob(digest, blob_io, size)
    end

    # Failed removals are logged, not raised: secondary verification catches a leftover tag.
    def remove_tags(names)
      return if names.empty?

      if container_repository.client.supports_tag_delete?
        names.each { |name| remove_tag(name) }
      else
        remove_tags_with_third_party_service(names)
      end
    end

    def remove_tag(name)
      return if container_repository.delete_tag(name)

      log_error "Error while removing tag #{name}: delete request failed"
    rescue StandardError => e
      log_error "Error while removing tag #{name}: #{e.message}"
    end

    # One service call for all names, so the dummy manifest is created and deleted only once.
    def remove_tags_with_third_party_service(names)
      result = ::Projects::ContainerRepository::ThirdParty::DeleteTagsService.new(container_repository, names).execute
      failed = names - Array(result[:deleted])

      return if failed.empty?

      log_error "Error while removing tags #{failed.join(', ')}: #{result[:message].presence || 'tag not deleted'}"
    rescue StandardError => e
      log_error "Error while removing tags #{names.join(', ')}: #{e.message}"
    end

    # Lists blobs or nested manifests
    # manifest['manifests'] is solely used by buildcache here because
    # normal image indexes only refer to other manifests, not blobs
    # manifest['blobs'] references the OCI artifacts
    # Some manifests (e.g. Cosign/Notation signatures, OCI 1.1 referrers)
    # have none of these keys; default to [] so we treat them as
    # "no blobs to pre-sync" rather than raising NoMethodError.
    def list_blobs(manifest)
      descriptors = manifest['layers'] || manifest['manifests'] || manifest['blobs'] || []

      blobs = descriptors.filter_map do |blob|
        blob['digest'] unless foreign_layer?(blob)
      end

      blobs.push(manifest.dig('config', 'digest')).compact
    end

    def foreign_layer?(layer)
      layer['mediaType'] == FOREIGN_MEDIA_TYPE
    end

    def primary_tags
      strong_memoize(:primary_tags) do
        client.repository_tag_names(repository_path).map do |tag|
          { name: tag, digest: client.repository_tag_digest(repository_path, tag) }
        end
      end
    end

    def secondary_tags
      strong_memoize(:secondary_tags) do
        container_repository.tags.map do |tag|
          { name: tag.name, digest: tag.digest }
        end
      end
    end

    def tags_to_sync
      primary_tags - secondary_tags
    end

    # A tag present on both sites with a different digest is overwritten by the push in sync_tag.
    def tags_to_remove
      primary_tag_names = primary_tags.to_set { |tag| tag[:name] }

      secondary_tags.reject { |tag| primary_tag_names.include?(tag[:name]) }
    end

    # The client for primary registry
    def client
      strong_memoize_with_expiration(:client, ContainerRepository.registry_client_expiration_time) do
        ContainerRegistry::Client.new(
          Gitlab.config.geo.registry_replication.primary_api_url,
          token: ::Auth::ContainerRegistryAuthenticationService.pull_access_token(repository_path)
        )
      end
    end
  end
end
