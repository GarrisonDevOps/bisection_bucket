# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- EE extension of CE Milestoneish module

module EE
  module Milestoneish
    extend ::Gitlab::Utils::Override

    override :milestone_issues
    def milestone_issues(user)
      super.preload(:current_status)
    end
  end
end

# rubocop:enable Gitlab/BoundedContexts
