# frozen_string_literal: true

module Todos
  # The review whose publication raised a review_submitted to-do item. The
  # todos table cannot take new columns, so the link lives beside it.
  class ReviewLink < ApplicationRecord
    self.table_name = 'todo_review_links'
    self.primary_key = :todo_id

    belongs_to :todo, inverse_of: :review_link, optional: false
    belongs_to :project, optional: false
    belongs_to :review, optional: false
  end
end
