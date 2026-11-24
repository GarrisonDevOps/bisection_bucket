# frozen_string_literal: true

module Ai
  module AiResource
    module Concerns
      module Noteable
        extend ActiveSupport::Concern
        def notes_with_limit(notes_limit:, is_duo_code_review: false)
          finder_options = { is_duo_code_review: is_duo_code_review }
          limited_notes = Ai::NotesForAiFinder.new(current_user, resource: resource, **finder_options).execute

          return [] if limited_notes.empty?

          notes_content = []
          sum_of_length = 0

          limited_notes.each_batch(of: 500) do |batch|
            batch.order_created_at_id_asc.pluck(:note).each do |note|
              sum_of_length += note.size
              break notes_content if sum_of_length >= notes_limit

              notes_content << note
            end
            break notes_content if sum_of_length >= notes_limit
          end

          notes_content
        end
      end
    end
  end
end
