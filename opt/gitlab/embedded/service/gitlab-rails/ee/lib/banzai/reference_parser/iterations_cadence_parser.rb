# frozen_string_literal: true

module Banzai
  module ReferenceParser
    class IterationsCadenceParser < BaseParser
      self.reference_type = :iterations_cadence

      def self.reference_class
        Iterations::Cadence
      end

      def references_relation
        Iterations::Cadence
      end

      def nodes_visible_to_user(user, nodes)
        records = records_for_nodes(nodes)

        nodes.select do |node|
          cadence = records[node]

          cadence && can_read_reference?(user, nil, cadence)
        end
      end

      def records_for_nodes(nodes)
        @iterations_cadences_for_nodes ||= grouped_objects_for_nodes(
          nodes,
          ::Iterations::Cadence.includes(:group), # rubocop:disable CodeReuse/ActiveRecord -- N+1
          self.class.data_attribute
        )
      end

      private

      def can_read_reference?(user, _ref_project, node)
        can?(user, :read_iteration_cadence, node.group)
      end
    end
  end
end
