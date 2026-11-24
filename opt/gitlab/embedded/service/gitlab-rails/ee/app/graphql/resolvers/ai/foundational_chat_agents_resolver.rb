# frozen_string_literal: true

module Resolvers
  module Ai
    class FoundationalChatAgentsResolver < BaseResolver
      description 'AI foundational chat agents.'

      type ::Types::Ai::FoundationalChatAgentType.connection_type, null: true

      # Foundational chat agents are loaded from an in-memory fixed-items model
      # rather than the database, so the per-item cost is negligible compared to
      # a DB-backed paginated list. Use a reduced multiplier (half the default 0.01)
      def self.complexity_multiplier(_args)
        0.005
      end

      argument :project_id, ::Types::GlobalIDType[Project],
        required: false,
        description: 'Global ID of the project where the chat is present.'

      argument :namespace_id, ::Types::GlobalIDType[::Namespace],
        required: false,
        description: 'Global ID of the namespace where the chat is present.'

      def resolve(*, project_id: nil, namespace_id: nil)
        ::Ai::FoundationalChatAgentsFinder.new(
          current_user,
          project_id: project_id,
          namespace_id: namespace_id
        ).execute
      end
    end
  end
end
