# frozen_string_literal: true

module Ai
  module Catalog
    module DuoWorkflowPayloadBuilder
      class V1AgentWrapper < V1
        include Gitlab::Utils::StrongMemoize
        extend ::Gitlab::Utils::Override

        def initialize(flow, flow_version, flow_environment:, params: {})
          @flow_version = flow_version

          super(
            flow,
            pinned_version_prefix: flow_version.version,
            flow_environment: flow_environment,
            params: params
          )
        end

        private

        attr_reader :flow_version

        override :flow_definition
        def flow_definition
          ::Ai::Catalog::FlowDefinition.new(flow, flow_version)
        end
        strong_memoize_attr :flow_definition
      end
    end
  end
end
