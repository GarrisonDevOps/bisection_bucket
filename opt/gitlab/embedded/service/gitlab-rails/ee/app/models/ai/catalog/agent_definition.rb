# frozen_string_literal: true

module Ai
  module Catalog
    class AgentDefinition < BaseDefinition
      def tool_names
        Ai::Catalog::BuiltInTool.where(id: tool_ids).map(&:name)
      end

      def system_prompt
        version.def_system_prompt
      end

      def user_prompt
        version.def_user_prompt
      end

      private

      def tool_ids
        Array(version.def_tools)
      end
    end
  end
end
