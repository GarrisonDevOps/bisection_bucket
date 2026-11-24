# frozen_string_literal: true

module Geo
  module Errors
    # SPIKE (gitlab-org/gitlab#602803): catalog of known Geo sync/verification errors.
    #
    # This is the single source of truth for error metadata. The Geo cleanup tools
    # (Geo::Tools) use it to detect and resolve known errors, and it is intended to back
    # the Geo Troubleshooting Dashboard metadata work in gitlab-org/gitlab#548532 (the
    # typed Geo::Errors::* classes would link to an entry here via their identifier).
    #
    # Built on the Fixed Items Model because this is static, version-controlled data.
    # The known-errors docs reference is generated from these entries, see the planned
    # `rake geo:tools:compile_docs` / `geo:tools:check_docs` tasks.
    class ErrorType
      include ActiveRecord::FixedItemsModel::Model

      SEVERITIES = %w[info warning critical].freeze
      SITES = %w[primary secondary].freeze

      # `match_pattern` matches against the free-text `last_sync_failure` column, because
      # the symptom taxonomy is finer-grained than the typed error classes, and because
      # existing registries only carry free-text failures (no error-class column yet, see
      # gitlab-org/gitlab#548529).
      ITEMS = [
        {
          id: 1,
          name: 'url_blocked',
          severity: 'warning',
          title: 'Download URL blocked',
          description: 'Object storage download URL was blocked by network filtering on ' \
            'the secondary site. Once the network fix is in place the failed registries ' \
            'just need to be resynced.',
          site: 'secondary',
          match_pattern: 'URL is blocked',
          resolvable: true,
          resolve_strategy: 'resync',
          docs: 'https://docs.gitlab.com/administration/geo/replication/troubleshooting/synchronization_verification/',
          troubleshooting_links: [],
          issues: ['https://gitlab.com/gitlab-org/gitlab/-/work_items/598514']
        },
        {
          id: 3,
          name: 'orphaned_uploads',
          severity: 'warning',
          title: 'Orphaned uploads',
          description: 'Uploads on the primary whose owning model is missing fail ' \
            'verification and can never be checksummed. The upload records can be deleted.',
          site: 'primary',
          match_pattern: 'The model which owns this upload is missing',
          resolvable: true,
          resolve_strategy: 'delete_orphaned_uploads',
          docs: 'https://docs.gitlab.com/administration/geo/replication/troubleshooting/synchronization_verification/',
          troubleshooting_links: [],
          issues: []
        },
        {
          id: 4,
          name: 'file_missing_on_primary',
          severity: 'warning',
          title: 'File is missing on the primary',
          description: 'Records on the primary reference a file that is no longer in ' \
            'storage, so Geo cannot checksum them. Secondaries report the same records as ' \
            '"The file is missing on the Geo primary site". Once you confirm the files are ' \
            'not recoverable, destroying the records propagates the deletion to every Geo ' \
            'site. Uploads and job artifacts are destroyed by the resolution; other data ' \
            'types are listed for manual cleanup.',
          site: 'primary',
          # Deliberately the "file does not exist" half of the "File is not checksummable"
          # family (Geo::Errors::ReplicableDoesNotExistError). The other half,
          # "File is not checksummable - <Model> <id> is excluded from verification", means the
          # record left the verification scope with its file intact, so matching on the shorter
          # text would put healthy records in front of a destructive resolution. Records whose
          # failure text predates the detailed message are picked up once verification retries
          # them.
          match_pattern: 'File is not checksummable - file does not exist at:',
          resolvable: true,
          resolve_strategy: 'destroy_replicables_with_missing_files',
          docs: 'https://docs.gitlab.com/administration/geo/replication/troubleshooting/' \
            'synchronization_verification/#clean-up-inconsistencies',
          troubleshooting_links: [],
          issues: []
        }
      ].freeze

      attribute :id, :integer
      attribute :name, :string
      attribute :severity, :string
      attribute :title, :string
      attribute :description, :string
      attribute :site, :string
      attribute :match_pattern, :string
      attribute :resolvable, :boolean
      attribute :resolve_strategy, :string
      attribute :docs, :string
      # Untyped on purpose: these hold array payloads, and a default attribute type would
      # coerce them to strings.
      attribute :troubleshooting_links
      attribute :issues
    end
  end
end
