# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Modes
        class Dap < Base
          def mode
            :dap
          end

          def enabled?
            true
          end

          def active?
            return false unless user
            return false if unconsented_duo_enterprise_usage?

            # Use agent platform if:
            # - DAP is enabled for the user on this container
            # - Code Review workflow is enabled on this container
            ::Ai::DuoAgentPlatform.available?(user: user, container: container) &&
              container.duo_code_review_dap_available?
          end

          private

          def unconsented_duo_enterprise_usage?
            return false unless user.assigned_to_duo_enterprise?(container)

            # Fast-path override: internal GitLab users bypass the consent requirement.
            return false if ::Feature.enabled?(:duo_code_review_dap_internal_users, user)

            # Explicitly check for consented use of DAP routing (recorded in namespaces_consents).
            !container.root_ancestor.consented_to?(:code_review_flow_dap_routing)
          end
        end
      end
    end
  end
end
