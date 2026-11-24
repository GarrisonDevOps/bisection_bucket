# frozen_string_literal: true

module Geo
  class MergeRequestDiffRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    self.table_name = 'merge_request_diff_registry'

    belongs_to :merge_request_diff, class_name: 'MergeRequestDiff'

    def self.model_class
      ::MergeRequestDiff
    end

    def self.model_foreign_key
      :merge_request_diff_id
    end
  end
end
