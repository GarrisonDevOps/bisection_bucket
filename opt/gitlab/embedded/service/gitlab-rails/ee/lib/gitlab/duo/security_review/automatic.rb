# frozen_string_literal: true

module Gitlab
  module Duo
    module SecurityReview
      # Decides when the Security Review Flow runs on a merge request without anyone
      # assigning it, and which flow trigger runs it.
      module Automatic
        FLOW_REFERENCE = ::Ai::Catalog::FoundationalFlow::SecurityReview::Definition::REFERENCE
        TRIGGER_TYPE = :merge_request_pipeline

        class << self
          # Projects opt in with the Business Logic scan profile's post review threads setting, which
          # the Security Review profile turns on. The Business Logic scan then skips the project.
          def available?(project)
            root_ancestor = project.root_ancestor

            post_review_threads?(project) &&
              ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(root_ancestor)
          end

          def post_review_threads?(project)
            ::Gitlab::SafeRequestStore.fetch([:bl_security_post_review_threads, project.id]) do
              profile = project.security_scan_profile_for(:business_logic, TRIGGER_TYPE)

              profile&.effective_configuration_for(TRIGGER_TYPE)&.dig(:post_review_threads) == true
            end
          end

          # Without a Security Review Flow trigger the flow cannot run, so the Business Logic scan runs as usual.
          def replaces_business_logic_scan?(project)
            available?(project) && trigger_for(project).present?
          end

          # Fork merge requests and authors who are not people are left to a manual review.
          def applicable?(merge_request)
            return false unless merge_request.author&.human?

            !merge_request.draft? && !merge_request.for_fork? && available?(merge_request.project)
          end

          def trigger_for(project)
            ::Ai::FlowTrigger
              .applicable_to_project(project, triggered_on: :assign_reviewer)
              .for_foundational_flow_references([FLOW_REFERENCE])
              .ordered_by_id
              .first
          end

          def permitted?(merge_request, user)
            project = merge_request.project
            return true if Ability.allowed?(user, :trigger_ai_flow, project) &&
              Ability.allowed?(user, :create_duo_workflow_for_ci, project)

            ::Gitlab::AppLogger.info(
              message: 'Automatic Duo security review skipped: author cannot run the flow',
              merge_request_id: merge_request.id,
              Labkit::Fields::GL_USER_ID => user.id
            )

            false
          end
        end
      end
    end
  end
end
