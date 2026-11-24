# frozen_string_literal: true

module Types
  module Govern
    # rubocop:disable Graphql/AuthorizeTypes -- Evaluations have no policy class of their
    # own; the policyEvaluations field authorizes against the parent container (group or
    # organization), matching the policies field.
    class PolicyEvaluationType < BaseObject
      graphql_name 'GovernPolicyEvaluation'
      description 'Recorded evaluation of a policy stored in the policy store.'

      # The Policy Store's stat tiles need totals, not pages: without a count on
      # the connection they would have to fetch every row they claim to count.
      connection_type_class ::Types::CountableConnectionType

      # A new field returning this type must declare its own directive, or nothing checks the token.
      authorize_granular_token skip_reason: :parent_authorizes

      field :id, ::Types::GlobalIDType[::Govern::PolicyEvaluation],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Global ID of the evaluation.'

      # Integer to match GovernPolicy.id, which stays an integer while the
      # policy store surfaces mirror the REST API.
      field :policy_id, GraphQL::Types::Int,
        null: false,
        method: :govern_policy_id,
        experiment: { milestone: '19.4' },
        description: 'ID of the policy that was evaluated.'

      field :trigger_type, ::Types::Govern::PolicyEvaluationTriggerTypeEnum,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Trigger that started the evaluation.'

      field :mode, ::Types::Govern::PolicyEvaluationModeEnum,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Enforcement mode of the policy at the time of the evaluation.'

      field :verdict, ::Types::Govern::PolicyEvaluationVerdictEnum,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Verdict the evaluation produced.'

      # rubocop:disable GraphQL/ExtractType -- policyVersion snapshots the version at evaluation
      # time; nesting it with policyId under a policy field would misrepresent it as live policy data.
      field :policy_version, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Version of the policy at the time of the evaluation.'
      # rubocop:enable GraphQL/ExtractType

      field :evaluated_at, Types::TimeType,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Timestamp of when the policy was evaluated.'

      field :project_id, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'ID of the project the evaluation ran for. ' \
          'Null when the evaluation was not scoped to a project.'

      field :project, ::Types::ProjectType,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Project the evaluation ran for. ' \
          'Null when the evaluation was not scoped to a project, or the project is not visible.'

      field :environment_id, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'ID of the environment the evaluation ran for. ' \
          'Null when the evaluation was not scoped to an environment.'

      field :user_id, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'ID of the user whose operation triggered the evaluation. ' \
          'Null when the evaluation was not triggered by a user.'

      field :violations, [::Types::Govern::PolicyViolationType],
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Violations the evaluation produced.'

      # project_id carries no foreign key, so the evaluations table stays extractable
      # (GOVERN-008). Loading by id keeps that true: one batched read per page instead
      # of a join across the Sec and Main databases.
      def project
        return if object.project_id.nil?

        # The loader preloads per-user policy state, so a batch shared across users would
        # hand one viewer another's permission cache.
        batch_key = [:govern_policy_evaluation_projects, object.organization_id, current_user&.id]

        BatchLoader::GraphQL.for(object.project_id).batch(key: batch_key) do |ids, loader|
          # project_id carries no foreign key, so a stale or mis-written id would otherwise
          # resolve to any project in the instance the viewer can read. Scoping to the
          # evaluation's organization keeps a foreign project off the policy's page.
          #
          # ProjectType authorizes every node, and webPath walks the route. Both are
          # per-project reads unless the whole page is preloaded here, and the policy
          # preloader alone leaves the feature and settings reads behind.
          # rubocop:disable CodeReuse/ActiveRecord -- no model scope covers a preload this field-specific
          projects = ::Project.in_organization(object.organization_id)
            .preload(:route, :project_feature, namespace: [:route, :namespace_settings])
            .id_in(ids).to_a
          # rubocop:enable CodeReuse/ActiveRecord
          ::Preloaders::ProjectPolicyPreloader.new(projects, current_user).execute

          projects.each { |project| loader.call(project.id, project) }
        end
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
