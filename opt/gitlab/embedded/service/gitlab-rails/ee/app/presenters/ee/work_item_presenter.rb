# frozen_string_literal: true

module EE
  module WorkItemPresenter
    extend ActiveSupport::Concern

    def promoted_to_epic_url
      work_item_transition = work_item.work_item_transition

      return unless work_item_transition.promoted?
      return unless Ability.allowed?(current_user, :read_epic, work_item_transition.promoted_to_epic)

      ::Gitlab::UrlBuilder.build(work_item_transition.promoted_to_epic)
    end
  end
end
