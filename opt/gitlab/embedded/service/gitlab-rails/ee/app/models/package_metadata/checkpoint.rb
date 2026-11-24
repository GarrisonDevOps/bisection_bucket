# frozen_string_literal: true

module PackageMetadata
  # Tracks the last synced position for supported types of package metadata
  # (advisories, licenses, etc) uniquedly defined by data_type, version_format,
  # purl_type.
  class Checkpoint < ApplicationRecord
    enum :purl_type, ::Enums::Sbom.purl_types
    enum :data_type, ::Enums::PackageMetadata.data_types
    enum :version_format, ::Enums::PackageMetadata.version_formats

    validates :data_type, presence: true
    validates :version_format, presence: true
    validates :sequence, presence: true, numericality: { only_integer: true }
    validates :chunk, presence: true, numericality: { only_integer: true }
    validates :purl_type, presence: true, unless: :cve_enrichment?
    validates :purl_type, uniqueness: { scope: [:data_type, :version_format] }

    # When each registry's advisories were last synced, for the dependency scanning
    # analyzer, which stops the scan when this is empty. Both version formats count,
    # so an instance whose first sync runs through v3 does not read as unsynced.
    # A registry partway through a full sync, first or a snapshot refresh, is left
    # out: its first chunk already carries the finished sync's timestamp.
    scope :advisory_purl_type_sequences, -> {
      where(data_type: 'advisories', full_sync_target_sequence: nil)
        .group(:purl_type).maximum(:sequence)
    }

    scope :for_dataset, ->(data_type, version_format) do
      where(data_type: data_type, version_format: version_format)
    end
    scope :for_finding_advisories, -> {
      where(data_type: [data_types[:advisories], data_types[:malware_advisories]])
    }
    scope :with_purl_types, ->(purl_types) { where(purl_type: purl_types) }
    scope :synced_since, ->(epoch_seconds) { where(sequence: epoch_seconds..) }

    # These components uniquely identify the last sync position for a
    # path determined by data_type_bucket_or_dir/version_format/purl_type.
    def self.with_path_components(data_type, version_format, purl_type)
      find_or_initialize_by(data_type: data_type, purl_type: purl_type, version_format: version_format)
    end

    # True while the full dataset still has to be read: never synced (sequence still
    # 0), or a snapshot is half-ingested (full_sync_target_sequence marker set), which
    # offline can reach long after the first sync. The v3 datasets use this to fetch
    # the /all snapshot rather than a delta. On the v2 path only CVE enrichment sets
    # the marker, and SyncService reads it directly.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/603628
    def full_dataset_pending?
      full_sync_target_sequence.present? || sequence.to_i == 0
    end
  end
end
