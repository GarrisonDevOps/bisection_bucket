# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowMergeRequest < ::ApplicationRecord
      include WorkflowLinkable

      self.table_name = :duo_workflows_workflow_merge_requests

      links_workflow_to :merge_request, class_name: 'MergeRequest', inverse_of: false

      enum :link_type, {
        # the merge request the flow was initiated against
        source: 0,
        # the merge request was created by the flow
        created: 1
      }, prefix: true

      scope :created_for_merge_request, ->(merge_request) {
        link_type_created.where(merge_request_id: merge_request)
      }

      scope :created_for_merge_requests_order_by_id_asc, ->(merge_request_ids) {
        created_for_merge_request(merge_request_ids).order(:id)
      }

      validates :idempotency_key, length: { maximum: 255 }

      def self.idempotency_key_for(workflow)
        flow = ::Ai::Catalog::FoundationalFlow[workflow.workflow_definition]
        return unless flow&.reuse_open_merge_request

        pipeline = WorkflowPipeline.link_type_source.find_by(workflow: workflow)&.pipeline
        return unless pipeline

        "#{workflow.workflow_definition}:pipeline-ref-sha:#{Digest::SHA256.hexdigest(pipeline.ref)}"
      end

      def self.open_merge_request_for(project_id, idempotency_key)
        where(project_id: project_id, idempotency_key: idempotency_key)
          .joins(:merge_request)
          .merge(::MergeRequest.opened)
          .first
          &.merge_request
      end
    end
  end
end
