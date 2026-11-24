# frozen_string_literal: true

module Types
  module Security
    # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent field level (ProjectType#scan_profile_statuses)
    class ScanProfileProjectStatusType < BaseObject
      graphql_name 'ScanProfileProjectStatus'
      description 'Status of a scan profile for a project.'

      field :scan_profile,
        type: ::Types::Security::ScanProfileType,
        null: false,
        description: 'Scan profile associated with the status.'

      field :status,
        type: Types::Security::ScanProfileStatusEnum,
        null: false,
        method: :computed_status,
        description: 'Computed display status: NOT_CONFIGURED, PENDING, ACTIVE, WARNING, FAILED, or STALE.'

      # rubocop:disable GraphQL/ExtractType -- counters are simple scalars, extracting a type adds unnecessary complexity
      field :consecutive_failure_count,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Number of consecutive failed scans.'

      field :consecutive_success_count,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Number of consecutive successful scans.'
      # rubocop:enable GraphQL/ExtractType

      field :last_scan_at,
        type: Types::TimeType,
        null: true,
        description: 'Timestamp of the last profile-triggered scan.'

      field :build_id,
        type: ::Types::GlobalIDType[::CommitStatus],
        null: true,
        description: 'ID of the last CI job that updated the status.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
