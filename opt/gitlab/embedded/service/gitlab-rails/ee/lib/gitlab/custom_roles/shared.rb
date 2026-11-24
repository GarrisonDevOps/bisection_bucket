# frozen_string_literal: true

module Gitlab
  module CustomRoles
    module Shared
      PARAMS = %i[
        title
        name
        description
        introduced_by_issue
        introduced_by_mr
        feature_category
        milestone
        group_ability
        project_ability
        requirements
        skip_seat_consumption
      ].freeze
    end
  end
end
