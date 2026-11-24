# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Availability
        class Namespace < Base
          alias_method :namespace, :container

          def available?
            check_duo_features(foundational_flows: false) do
              next true if namespace.duo_code_review_dap_available?

              # Classic Duo Enterprise flow fallback
              namespace.has_active_add_on_purchase?([:duo_enterprise])
            end
          end

          def depth_settings_available?
            return false if ::Feature.disabled?(:duo_code_review_standard_flow, namespace.root_ancestor)

            check_duo_features(beta: true)
          end

          def decisions_settings_available?
            return false if ::Feature.disabled?(:duo_code_review_decisions, namespace)

            check_duo_features(beta: true) { available? }
          end

          private

          def duo_beta_features_enabled?
            namespace.root_ancestor.duo_beta_flows_enabled?
          end
        end
      end
    end
  end
end
