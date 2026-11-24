# frozen_string_literal: true

module Ai
  module Catalog
    # Policy subject only: pairs a group inheritance record with the project it is used in.
    class ItemConsumerAuthorizationSubject
      attr_reader :item_consumer, :project

      def initialize(item_consumer, project)
        @item_consumer = item_consumer
        @project = project
      end

      def id
        "#{item_consumer.id}-#{project.id}"
      end

      def inherited_by_project?
        item_consumer.inheritance? && project.namespace.traversal_ids.include?(item_consumer.group_id)
      end
    end
  end
end
