# frozen_string_literal: true

module Mutations
  module SecurityPolicy
    class ResyncSecurityPolicies < BaseMutation
      graphql_name 'ResyncSecurityPolicies'
      description 'Triggers a resynchronization of security policies linked to the given project or group (`full_path`)'

      include FindsProjectOrGroupForSecurityPolicies

      authorize :update_security_orchestration_policy_project

      authorize_granular_token permissions: :update_security_policy,
        boundaries: [
          { boundary_argument: :full_path, boundary_type: :project },
          { boundary_argument: :full_path, boundary_type: :group }
        ]

      argument :full_path, GraphQL::Types::String,
        required: true,
        description: 'Full path of the project or group.'

      argument :relationship, Types::SecurityOrchestration::RelationshipTypeEnum,
        required: false,
        description: 'Relationship of the policies to resync.',
        default_value: :direct

      def resolve(args)
        project_or_group = authorized_find!(**args)

        if resync_throttled?(project_or_group, args[:relationship])
          return { errors: [s_('SecurityOrchestration|Policies were resynchronized recently. Try again in an hour.')] }
        end

        result = ::Security::SecurityOrchestrationPolicies::ResyncPoliciesService.new(
          container: project_or_group,
          current_user: current_user,
          params: { relationship: args[:relationship] }
        ).execute

        {
          errors: result[:status] == :success ? [] : [result[:message]]
        }
      end

      private

      # A direct resync fans out to every project the configuration covers, so repeated calls stack full syncs.
      # Inherited resyncs only touch the given project, and calls without a configuration do no work.
      def resync_throttled?(project_or_group, relationship)
        return false unless relationship == :direct && project_or_group.security_orchestration_policy_configuration

        ::Gitlab::ApplicationRateLimiter.throttled?(:security_policies_resync,
          scope: ::Gitlab::ApplicationRateLimiter.parent_scope(project_or_group))
      end
    end
  end
end
