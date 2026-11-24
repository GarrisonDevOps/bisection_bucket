# frozen_string_literal: true

module Resolvers
  module Cd
    class DefinitionStepsResolver < BaseResolver
      type [::Types::Cd::DefinitionStepType], null: true

      alias_method :flow_definition, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        document = flow_document
        return unless document

        ::Cd::ApplicationFlowDefinitions::DefinitionSteps::Builder.new(
          document: document,
          flow_definition: flow_definition
        ).steps
      end

      private

      # A blank definition parses to nil, which Document treats as "no steps" (returns []).
      # Psych::Exception (unparseable YAML) returns nil -- distinct from [] -- so callers
      # can tell "unknown structure" from "genuinely empty". Errno::ENOENT is tracked
      # separately so missing files in production are observable, even though the GraphQL
      # response returns nil for backward compatibility with test environments.
      # YAML.safe_load with no permitted_classes is safe here because the flow definition
      # is validated on write and only contains basic YAML types (hashes, arrays, strings, numbers).
      def flow_document
        ::Cd::ApplicationFlowDefinitions::Document.new(YAML.safe_load(flow_definition.definition))
      rescue Psych::Exception
        nil
      rescue Errno::ENOENT => e
        Gitlab::ErrorTracking.track_exception(e, flow_definition_id: flow_definition.id)
        nil
      end
    end
  end
end
