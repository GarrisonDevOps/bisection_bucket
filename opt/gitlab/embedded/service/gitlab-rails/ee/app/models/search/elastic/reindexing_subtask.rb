# frozen_string_literal: true

module Search
  module Elastic
    class ReindexingSubtask < ApplicationRecord
      self.table_name = 'elastic_reindexing_subtasks'

      belongs_to :elastic_reindexing_task, class_name: 'Search::Elastic::ReindexingTask'

      has_many :slices, class_name: 'Elastic::ReindexingSlice',
        foreign_key: :elastic_reindexing_subtask_id, inverse_of: :elastic_reindexing_subtask

      validates :index_name_from, :index_name_to, presence: true

      scope :order_by_alias_name_asc, -> { order(alias_name: :asc) }
    end
  end
end
