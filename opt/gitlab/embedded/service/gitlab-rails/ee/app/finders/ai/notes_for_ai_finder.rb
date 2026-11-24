# frozen_string_literal: true

module Ai
  class NotesForAiFinder
    attr_reader :resource, :current_user, :is_duo_code_review

    def initialize(current_user, resource:, is_duo_code_review: false)
      @current_user = current_user
      @resource = resource
      @is_duo_code_review = is_duo_code_review
    end

    def execute
      return Note.none unless Ability.allowed?(current_user, :read_note, resource)

      limited_notes = resource.notes.user.without_hidden.order_created_at_id_asc

      return limited_notes.not_internal if @is_duo_code_review
      return limited_notes.not_internal unless Ability.allowed?(current_user, :read_internal_note, resource)

      limited_notes
    end
  end
end
