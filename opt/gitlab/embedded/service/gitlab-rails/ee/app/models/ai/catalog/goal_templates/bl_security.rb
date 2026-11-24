# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      # Goal template for the Business Logic Security Scan flow. The trigger passes
      # a Ci::Pipeline: an MR head pipeline resolves to the MR IID, anything else to
      # the pipeline URL (which the flow's goal validator refuses). The IID only
      # identifies the merge request; `target_files` (set by FoundationalFlow::BlSecurity::Context
      # from its changes) limits the scan to the diff.
      class BlSecurity < Base
        def self.resolve(event_type:, resource:, user_input: nil, params: {}) # rubocop:disable Lint/UnusedMethodArgument -- interface contract from Base
          raise ArgumentError, 'resource must not be nil' unless resource

          # A fork's merge request gets the pipeline URL instead of an IID: when its
          # pipeline runs in the fork, the IID would name some other merge request.
          # The flow's goal validator refuses fork merge requests either way.
          merge_request = merge_request_for(resource)
          return merge_request.iid.to_s if merge_request && !merge_request.for_fork?

          ::Gitlab::UrlBuilder.build(resource)
        end

        # A merge request pipeline's own merge request, or, for a branch pipeline,
        # the newest open merge request into the pipeline's project whose head
        # pipeline it is. A fork's merge request into its upstream never matches.
        def self.merge_request_for(pipeline)
          return unless pipeline.is_a?(::Ci::Pipeline)

          pipeline.merge_request ||
            pipeline.project.merge_requests.opened.order(id: :desc).find_by(head_pipeline_id: pipeline.id)
        end
      end
    end
  end
end
