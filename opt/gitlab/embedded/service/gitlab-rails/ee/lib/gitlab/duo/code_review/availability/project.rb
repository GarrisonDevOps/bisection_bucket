# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Availability
        class Project < Base
          alias_method :project, :container

          def available?
            check_duo_features(foundational_flows: false) do
              next true if project.duo_code_review_dap_available?

              # Classic Duo Enterprise flow fallback
              project.namespace.has_active_add_on_purchase?([:duo_enterprise])
            end
          end

          def depth_settings_available?
            return false if ::Feature.disabled?(:duo_code_review_standard_flow, project.root_ancestor)

            check_duo_features(beta: true)
          end

          def decisions_settings_available?
            return false if ::Feature.disabled?(:duo_code_review_decisions, project)

            check_duo_features(beta: true) { available? }
          end

          def approval_counts_available?
            # Called per merge request when wrapping approval rules, each with its own
            # Project instance, so memoizing on self would not help.
            ::Gitlab::SafeRequestStore.fetch([:duo_code_review_approval_counts, project.id]) do
              next false unless project.duo_code_review_decisions_enabled &&
                project.duo_code_review_approval_counts_enabled

              decisions_settings_available?
            end
          end

          private

          def duo_beta_features_enabled?
            project.root_ancestor.duo_beta_flows_enabled?
          end
        end
      end
    end
  end
end
