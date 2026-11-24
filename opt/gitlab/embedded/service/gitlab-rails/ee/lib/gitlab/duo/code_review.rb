# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      extend Availability

      LITE_DEPTH = 'lite'
      STANDARD_DEPTH = 'standard'
      DEPTHS = [LITE_DEPTH, STANDARD_DEPTH].freeze
      # deep_code_review is the old name of standard_code_review, kept for workflows that ran under it.
      DEPTHS_BY_FLOW_ID = {
        'code_review' => :lite, 'standard_code_review' => :standard, 'deep_code_review' => :standard
      }.freeze
      DEPTH_VALUES = { LITE_DEPTH => 0, STANDARD_DEPTH => 1 }.freeze

      module_function

      def enabled?(user:, container:)
        ModeResolver.new(user: user, container: container).enabled?
      end

      def mode(user:, container:)
        ModeResolver.new(user: user, container: container).mode
      end

      def dap?(user:, container:)
        mode(user:, container:) == :dap
      end

      # The flag is the kill switch; the root group's beta setting and the project's
      # cascading setting decide where Standard reviews are available.
      def standard_available?(project:)
        return false unless project
        return false unless ::Feature.enabled?(:duo_code_review_standard_flow, project.root_ancestor)
        return false unless project.root_ancestor.duo_beta_flows_enabled?

        !!project.duo_code_review_depth_allowed
      end

      # The depth of the code review flow that actually ran, as recorded by DWS.
      def depth_for(workflow)
        return if workflow.flow_metadata_json.blank?

        metadata = ::Gitlab::Json.safe_parse(workflow.flow_metadata_json)
        DEPTHS_BY_FLOW_ID[metadata['flow_id']] if metadata.is_a?(Hash)
      end
    end
  end
end
