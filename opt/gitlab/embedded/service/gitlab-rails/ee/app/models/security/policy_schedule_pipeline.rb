# frozen_string_literal: true

module Security
  class PolicySchedulePipeline < ApplicationRecord
    include Ci::Partitionable::AssociationFinder

    self.table_name = 'security_policy_schedule_pipelines'

    belongs_to :security_policy, class_name: 'Security::Policy'
    belongs_to :pipeline, class_name: 'Ci::Pipeline'
    partitionable_belongs_to_loader :pipeline
    belongs_to :project

    validates :security_policy, :pipeline, :project, presence: true
    validates :pipeline, uniqueness: true

    scope :for_policy, ->(policy) { where(security_policy: policy) }
    scope :for_project, ->(project) { where(project: project) }
    scope :preload_pipeline, -> { with_partition_aware_preload.preload(:pipeline) }
    scope :preload_pipeline_and_project_route, -> { preload_pipeline.preload(project: :route) }
    scope :order_by_id_desc, -> { order(id: :desc) }

    # The limit of 100 is based on: daily schedule (most frequent) + 1 month time window = ~31 max pipelines.
    # We use 100 to provide buffer for edge cases.
    CANCELABLE_PIPELINE_LOOKUP_LIMIT = 100

    def self.cancelable_pipelines_for(security_policy:, project:)
      pipeline_ids = for_policy(security_policy)
                       .for_project(project)
                       .order_by_id_desc
                       .limit(CANCELABLE_PIPELINE_LOOKUP_LIMIT)
                       .pluck(:pipeline_id)
      return Ci::Pipeline.none if pipeline_ids.empty?

      Ci::Pipeline.id_in(pipeline_ids).cancelable
    end

    def self.safe_create(security_policy:, pipeline:, project:)
      create!(security_policy: security_policy, pipeline: pipeline, project: project)
    rescue ActiveRecord::RecordNotUnique
      nil
    rescue ActiveRecord::RecordInvalid => e
      Gitlab::ErrorTracking.track_exception(e,
        security_policy_id: security_policy.id,
        pipeline_id: pipeline.id
      )
    end
  end
end
