# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module JwtV2
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        private

        override :ci_claims
        def ci_claims
          super.merge(policy_claims)
        end

        def policy_claims
          policy_options = build.options[:policy]
          return {} if policy_options&.dig(:sha).blank? || policy_options&.dig(:project_id).blank?

          policy_project = ::Project.find_by_id(policy_options[:project_id])
          if policy_project.nil?
            ::Gitlab::AppLogger.warn(
              message: 'Policy project not found when generating JWT claims',
              project_id: policy_options[:project_id],
              build_id: build.id
            )
            return {}
          end

          {
            job_config: {
              url: ::Security::OrchestrationPolicyConfiguration.policy_project_configuration_url(
                policy_project,
                policy_options[:sha]
              ),
              sha: policy_options[:sha]
            }
          }
        end
        strong_memoize_attr :policy_claims
      end
    end
  end
end
