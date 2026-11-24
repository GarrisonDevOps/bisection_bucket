# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Availability
        class Base
          def initialize(container)
            @container = container
          end

          def available?
            raise NotImplementedError
          end

          # Thin wrapper around #available?, kept for historical reasons.
          def automatic_review_available?
            available?
          end

          def default_depth
            return ::Gitlab::Duo::CodeReview::LITE_DEPTH unless depth_settings_available?
            return ::Gitlab::Duo::CodeReview::LITE_DEPTH unless container.duo_code_review_depth_allowed

            container.duo_code_review_default_depth
          end

          def decisions_settings_available?
            raise NotImplementedError
          end

          def depth_settings_available?
            raise NotImplementedError
          end

          private

          attr_reader :container

          def duo_features_enabled?
            container.duo_features_enabled
          end

          def duo_beta_features_enabled?
            raise NotImplementedError
          end

          def duo_foundational_flows_enabled?
            container.duo_foundational_flows_enabled
          end

          def check_duo_features(beta: false, foundational_flows: true, &)
            return false unless duo_features_enabled?
            return false if beta && !duo_beta_features_enabled?
            return false if foundational_flows && !duo_foundational_flows_enabled?

            block_given? ? yield : true
          end
        end
      end
    end
  end
end
