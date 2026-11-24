# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      # Builds the legacy merge_request and pipeline categories fix_pipeline reads.
      module PipelineContextBuilder
        VERSION = "1.0.0"

        def self.build(pipeline, merge_request: pipeline.all_merge_requests_by_recency.opened.first)
          [
            Envelope.wrap(category: "merge_request", fields: merge_request_fields(merge_request), version: VERSION),
            Envelope.wrap(
              category: "pipeline",
              fields: { "source_branch" => pipeline.source_ref, "source" => pipeline.source },
              version: VERSION
            )
          ]
        end

        def self.merge_request_fields(merge_request)
          return { "url" => "" } unless merge_request

          { "url" => ::Gitlab::UrlBuilder.build(merge_request), "author_id" => merge_request.author_id.to_s }
        end
        private_class_method :merge_request_fields
      end
    end
  end
end
