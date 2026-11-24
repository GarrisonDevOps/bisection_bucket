# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Modes
        class Classic < Base
          def mode
            :classic
          end

          def enabled?
            true
          end

          def active?
            return false unless user

            Ability.allowed?(user, :access_ai_review_mr, container) &&
              ::Gitlab::Llm::FeatureAuthorizer.new(
                container: container,
                feature_name: :review_merge_request,
                user: user
              ).allowed?
          end
        end
      end
    end
  end
end
