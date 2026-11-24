# frozen_string_literal: true

module Banzai
  module FeatureFlags
    class << self
      def markdown_placeholders_enabled?(*containers)
        actors_for(containers).any? do |actor|
          ::Feature.enabled?(:markdown_placeholders, actor, type: :gitlab_com_derisk)
        end
      end

      def glql_load_on_click_enabled?(*containers)
        actors_for(containers).any? do |actor|
          ::Feature.enabled?(:glql_load_on_click, actor, type: :ops)
        end
      end

      def allow_iframes_in_markdown_enabled?(*containers)
        actors_for(containers).any? do |actor|
          ::Feature.enabled?(:allow_iframes_in_markdown, actor, type: :wip)
        end
      end

      private

      def actors_for(containers)
        containers.flat_map { |container| container_actors(container) }.uniq
      end

      def container_actors(container)
        case container
        when Project then [*group_actors(container.group), container]
        when Namespaces::ProjectNamespace then container_actors(container.project)
        when Group then group_actors(container)
        else []
        end
      end

      def group_actors(group)
        return [] unless group

        [group.root_ancestor, group].uniq
      end
    end
  end
end
