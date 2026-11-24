# frozen_string_literal: true

module Ai
  module Catalog
    class FlowDefinition < BaseDefinition
      def steps
        raw_steps.each_with_index.filter_map do |step, i|
          agent = agent_map[step['agent_id']]

          step.except('agent_id')
          .merge(
            'unique_id' => "#{agent.id}/#{i}",
            'agent' => agent,
            'idx' => i
          ).symbolize_keys
        end
      end
      strong_memoize_attr :steps

      private

      def agent_map
        @agent_map ||= preload_agents_by_id
      end

      def raw_steps
        version.def_steps
      end

      def preload_agents_by_id
        agent_ids = raw_steps.pluck('agent_id') # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- this is fetching data from a jsonb column.
        agents = Ai::Catalog::Item.where(id: agent_ids)
        agents.index_by(&:id)
      end
    end
  end
end
