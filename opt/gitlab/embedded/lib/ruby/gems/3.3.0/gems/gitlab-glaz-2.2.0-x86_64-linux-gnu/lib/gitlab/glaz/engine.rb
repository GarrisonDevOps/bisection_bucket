# frozen_string_literal: true

require "json"

module Gitlab
  module Glaz
    # Wraps a native Glaz::PermissionCheckEngine instance.
    #
    # The Cedar schema is fixed for the lifetime of the engine: it is loaded
    # exactly once at construction and cannot be re-loaded; build a new Engine
    # to change it. The policy set can be replaced at any time with
    # #load_policies.
    #
    # Schemas must declare `User` and `Resource` entity types and declare
    # each checkable action with `appliesTo { principal: [User], resource:
    # [Resource], ... }`, because the engine builds `User::"<subject_uuid>"` and
    # `Resource::"<object_uuid>"` entity UIDs for every check. The engine also
    # injects `permissions` (a Set<Action> containing the checked action)
    # into the Cedar context, so an action's declared context type must include
    # `permissions: Set<Action>` alongside any custom attributes.
    class Engine
      # @param schema [String] Cedar schema source (`.cedarschema` DSL).
      # @param policies [String] Cedar policy source, validated against the
      #   schema; ArgumentError is raised when either does not parse or the
      #   policies do not validate.
      def initialize(schema:, policies:)
        @native = ::Glaz::PermissionCheckEngine.new
        @native.load_schema(schema)
        @native.load_policies(policies)
      end

      # Replace the active policy set with the given Cedar policy source,
      # validated against the engine's schema. Raises ArgumentError when the
      # source does not parse or validate; the previous policies then remain
      # active. The swap is atomic with respect to concurrent checks.
      def load_policies(source)
        @native.load_policies(source)
      end

      # Evaluate whether the subject may perform +action+ on the object.
      #
      # @param context [Hash] ABAC attributes made available to policies as the
      #   Cedar context; must match the context type the schema declares for
      #   the checked action.
      # @return [Hash] { allowed: Boolean, reason: String }
      def check_action(subject_uuid:, object_uuid:, action:, context: {})
        request = ::Glaz::CheckRequest.encode(
          ::Glaz::CheckRequest.new(
            subject: ::Relationships::V1::Principal.new(id: subject_uuid),
            action: action,
            object: ::Relationships::V1::Object.new(id: object_uuid),
            context: context.to_json
          )
        )

        @native.check_action(request)
      end
    end
  end
end
