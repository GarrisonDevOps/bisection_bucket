# frozen_string_literal: true

module Mutations
  module Releases
    class Create < Base
      graphql_name 'ReleaseCreate'
      description "Creates a release. #{RELEASE_WRITES_LIMIT_DESCRIPTION}"

      field :release,
        Types::ReleaseType,
        null: true,
        description: 'Release after mutation.'

      field :warnings,
        [GraphQL::Types::String],
        null: true,
        description: 'Non-fatal problems encountered while creating the release. The release was still created. ' \
          'Returns a warning, only if the `release_evidence_size_limit` feature flag is enabled, when the release ' \
          'evidence would exceed the `release_evidence_max_size_bytes` application setting even without its ' \
          'issues: no evidence was collected, or, for an upcoming release, none is collected on its release ' \
          'date if it still exceeds the limit then.'

      argument :tag_name, GraphQL::Types::String,
        required: true, as: :tag,
        description: 'Name of the tag to associate with the release.'

      argument :tag_message, GraphQL::Types::String,
        required: false,
        description: 'Message to use if creating a new annotated tag.'

      argument :ref, GraphQL::Types::String,
        required: false,
        description: 'Commit SHA or branch name to use if creating a new tag.'

      argument :name, GraphQL::Types::String,
        required: false,
        description: 'Name of the release.'

      argument :description, GraphQL::Types::String,
        required: false,
        description: 'Description (also known as "release notes") of the release.'

      argument :released_at, Types::TimeType,
        required: false,
        description: 'Date and time for the release. Defaults to the current time. Expected in ISO 8601 format ' \
          '(`2019-03-15T08:00:00Z`). Only provide this field if creating an upcoming or historical release.'

      argument :milestones, [GraphQL::Types::String],
        required: false,
        description: 'Title of each milestone the release is associated with. ' \
          'GitLab Premium customers can specify group milestones.'

      argument :assets, Types::ReleaseAssetsInputType,
        required: false,
        description: 'Assets associated to the release.'

      authorize :create_release
      authorize_granular_token permissions: :create_release,
        boundary_argument: :project_path, boundary_type: :project

      def resolve(project_path:, assets: nil, **scalars)
        project = authorized_find!(project_path)

        params = {
          **scalars,
          assets: assets.to_h
        }.with_indifferent_access

        result = ::Releases::CreateService.new(project, current_user, params).execute

        if result[:status] == :success
          {
            release: result[:release],
            warnings: result[:warnings],
            errors: []
          }
        else
          {
            release: nil,
            warnings: [],
            errors: [result[:message]]
          }
        end
      end
    end
  end
end
