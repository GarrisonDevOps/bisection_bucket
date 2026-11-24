# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Availability
        class Instance < Base
          alias_method :application_setting, :container

          def available?
            check_duo_features(foundational_flows: false) do
              # Start with Duo Enterprise (classic flow)
              # Duo Enterprise is always available when the add-on is active, regardless of feature flags
              add_ons = [:duo_enterprise]

              # Auto code review is hidden for Duo Core and Pro until the flow settings are in the admin UI.
              # TODO: Re-enable once https://gitlab.com/gitlab-org/gitlab/-/issues/584603 is resolved:
              # add_ons += [:duo_pro, :duo_core, :self_hosted_dap]

              ::GitlabSubscriptions::AddOnPurchase.for_active_add_ons(add_ons, :instance).any?
            end
          end

          def depth_settings_available?
            return false if ::Feature.disabled?(:duo_code_review_standard_flow, :instance)

            check_duo_features(beta: true)
          end

          def decisions_settings_available?
            return false if ::Feature.disabled?(:duo_code_review_decisions, :instance)

            check_duo_features(beta: true) { available? }
          end

          private

          def duo_beta_features_enabled?
            application_setting.instance_level_ai_beta_features_enabled?
          end
        end
      end
    end
  end
end
