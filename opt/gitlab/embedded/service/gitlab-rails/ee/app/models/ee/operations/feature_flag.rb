# frozen_string_literal: true

module EE
  module Operations # rubocop:disable Gitlab/BoundedContexts -- This is an existing legacy module
    module FeatureFlag
      extend ActiveSupport::Concern

      prepended do
        has_many :feature_flag_issues
        has_many :issues, through: :feature_flag_issues, inverse_of: :feature_flags

        def related_issues(current_user, preload:)
          issues = ::Issue
            .select('issues.*, operations_feature_flags_issues.id AS link_id')
            .joins(:feature_flag_issues)
            .where(operations_feature_flags_issues: { feature_flag_id: id })
            .order('operations_feature_flags_issues.id ASC')
            .includes(preload)

          Ability.issues_readable_by_user(issues, current_user)
        end
      end
    end
  end
end
