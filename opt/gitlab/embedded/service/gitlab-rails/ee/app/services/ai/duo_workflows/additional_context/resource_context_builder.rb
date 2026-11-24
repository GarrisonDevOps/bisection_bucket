# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      # Builds agent_platform_resource_context (schema: json_schemas/agent_platform/agent_platform_resource_context).
      module ResourceContextBuilder
        DEFAULTS = {
          "resource_type" => "",
          "resource_id" => "",
          "resource_web_url" => "",
          "pipeline_id" => "",
          "pipeline_web_url" => "",
          "pipeline_source_branch" => "",
          "merge_request_id" => "",
          "merge_request_diff_sha" => "",
          "merge_request_web_url" => "",
          "work_item_id" => "",
          "work_item_web_url" => ""
        }.freeze

        # Sentinel default for `merge_request:` so a caller that already resolved the
        # pipeline's MR (e.g. RunService, to avoid querying for it twice) can pass it
        # straight through, including `nil` meaning "resolved: none found". Callers with
        # no pre-resolved value just omit the kwarg and pipeline_fields queries it itself.
        NOT_PROVIDED = :not_provided
        private_constant :NOT_PROVIDED

        # nil when resource is nil or a type this envelope doesn't cover.
        def self.build(resource, merge_request: NOT_PROVIDED)
          fields =
            case resource
            when ::Ci::Pipeline  then pipeline_fields(resource, merge_request)
            when ::MergeRequest  then merge_request_fields(resource)
            when ::Issue         then work_item_fields(resource)
            when ::Vulnerability then vulnerability_fields(resource)
            end

          return unless fields

          DEFAULTS.merge(fields)
        end

        def self.pipeline_fields(pipeline, merge_request)
          # A branch pipeline has no single FK to "the" MR, so the most recent open MR
          # off that branch stands in (matches RunService's legacy merge_request category).
          # merge_request_id can be foreign to this project for a fork MR; see the schema.
          merge_request = pipeline.all_merge_requests_by_recency.opened.first if merge_request == NOT_PROVIDED
          web_url = ::Gitlab::UrlBuilder.build(pipeline)

          {
            "resource_type" => "pipeline",
            "resource_id" => pipeline.to_global_id.to_s,
            "resource_web_url" => web_url,
            "pipeline_id" => pipeline.to_global_id.to_s,
            "pipeline_web_url" => web_url,
            "pipeline_source_branch" => pipeline.source_ref,
            "merge_request_id" => merge_request ? merge_request.iid.to_s : "",
            "merge_request_diff_sha" => merge_request ? merge_request.diff_head_sha.to_s : "",
            "merge_request_web_url" => merge_request ? ::Gitlab::UrlBuilder.build(merge_request) : ""
          }
        end
        private_class_method :pipeline_fields

        def self.merge_request_fields(merge_request)
          pipeline = merge_request.diff_head_pipeline
          web_url = ::Gitlab::UrlBuilder.build(merge_request)

          {
            "resource_type" => "merge_request",
            "resource_id" => merge_request.iid.to_s,
            "resource_web_url" => web_url,
            "pipeline_id" => pipeline ? pipeline.to_global_id.to_s : "",
            "pipeline_web_url" => pipeline ? ::Gitlab::UrlBuilder.build(pipeline) : "",
            "pipeline_source_branch" => pipeline ? pipeline.source_ref : "",
            "merge_request_id" => merge_request.iid.to_s,
            "merge_request_diff_sha" => merge_request.diff_head_sha.to_s,
            "merge_request_web_url" => web_url
          }
        end
        private_class_method :merge_request_fields

        def self.work_item_fields(issue)
          web_url = ::Gitlab::UrlBuilder.build(issue)

          {
            "resource_type" => "work_item",
            "resource_id" => issue.iid.to_s,
            "resource_web_url" => web_url,
            "work_item_id" => issue.iid.to_s,
            "work_item_web_url" => web_url
          }
        end
        private_class_method :work_item_fields

        def self.vulnerability_fields(vulnerability)
          {
            "resource_type" => "vulnerability",
            # Plain numeric ID, not a global ID: the tools that take a vulnerability ID
            # (e.g. get_vulnerability_details) expect this form.
            "resource_id" => vulnerability.id.to_s,
            "resource_web_url" => ::Gitlab::UrlBuilder.build(vulnerability)
          }
        end
        private_class_method :vulnerability_fields
      end
    end
  end
end
