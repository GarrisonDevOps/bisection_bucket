# frozen_string_literal: true

module Analytics
  module Dashboards
    class Panel
      attr_reader :title, :title_icon, :tooltip, :grid_attributes,
        :config_project, :query_overrides, :container

      def self.from_data(panel_yaml, config_project, container)
        return if panel_yaml.nil?

        panel_yaml.map do |panel|
          new(panel: panel, config_project: config_project, container: container)
        end
      end

      private_class_method :new

      def initialize(panel:, config_project:, container:)
        @title = panel['title']
        @title_icon = panel['titleIcon']
        @tooltip = panel['tooltip']
        @config_project = config_project
        @container = container
        @grid_attributes = panel['gridAttributes']
        @query_overrides = panel['queryOverrides']
        @views_config = panel['views']
        @visualization_config = panel['visualization']
      end

      # Built on demand because custom visualizations are read from the repository,
      # so constructing a panel must not hit Gitaly on its own.
      def visualization
        @visualization ||= build_visualization(@visualization_config)
      end

      def views
        @views ||= build_views(@views_config)
      end

      private

      def build_views(views_config)
        return [] unless views_config.is_a?(Array)

        views_config.map do |view|
          {
            text: view['text'],
            visualization: build_visualization(view['visualization'])
          }
        end
      end

      def build_visualization(visualization_config)
        return if visualization_config.blank?

        if visualization_config.is_a?(String)
          Visualization.from_file(
            filename: visualization_config,
            config_project: config_project,
            container: container
          )
        else
          Visualization.from_data(
            data: visualization_config,
            container: container
          )
        end
      end
    end
  end
end
