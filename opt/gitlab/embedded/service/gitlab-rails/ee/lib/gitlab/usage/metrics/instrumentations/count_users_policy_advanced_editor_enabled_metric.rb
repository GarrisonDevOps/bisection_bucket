# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountUsersPolicyAdvancedEditorEnabledMetric < DatabaseMetric
          operation :count

          relation do
            ::UserPreference.with_user.policy_advanced_editor.merge(::User.active)
          end
        end
      end
    end
  end
end
