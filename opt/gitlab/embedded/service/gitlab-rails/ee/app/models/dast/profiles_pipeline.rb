# frozen_string_literal: true

module Dast
  class ProfilesPipeline < ::SecApplicationRecord
    include BulkInsertSafe
    include Ci::Partitionable::AssociationFinder

    self.table_name = 'dast_profiles_pipelines'

    belongs_to :ci_pipeline, class_name: 'Ci::Pipeline', optional: false
    partitionable_belongs_to_loader :ci_pipeline
    belongs_to :dast_profile, class_name: 'Dast::Profile', optional: false
  end
end
