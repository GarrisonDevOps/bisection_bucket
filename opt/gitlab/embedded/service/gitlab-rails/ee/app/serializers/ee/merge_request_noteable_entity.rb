# frozen_string_literal: true

module EE
  module MergeRequestNoteableEntity
    extend ActiveSupport::Concern

    prepended do
      expose :require_password_to_approve do |merge_request|
        merge_request.target_project.require_password_to_approve?
      end

      expose :can_resolve_discussions_with_ai do |merge_request|
        merge_request.can_resolve_discussions_with_ai?(current_user)
      end
    end
  end
end
