# frozen_string_literal: true

module Geo
  module Console
    # Actions and Menus are types of Choices.
    #
    # A Choice has a name, a way to open itself, and optionally a previous Choice to return to.
    class Choice
      def initialize(input_stream: $stdin, output_stream: $stdout, referer: nil)
        @input_stream = input_stream
        @output_stream = output_stream
        @referer = referer
      end

      def name
        raise NotImplementedError, "#{self.class} must implement ##{__method__}"
      end

      def open
        raise NotImplementedError, "#{self.class} must implement ##{__method__}"
      end

      def header
        <<~HEADER
          --------------------------------------------------------------------------------
          Geo Developer Console | #{current_site}
          #{name}
          --------------------------------------------------------------------------------
        HEADER
      end

      private

      def current_site
        if Gitlab::Geo.primary?
          "Geo Primary Site | #{Gitlab::Geo.current_node.name}"
        elsif Gitlab::Geo.org_migration_target?
          "Org Migration Target Cell | #{Gitlab::Geo.current_node.name}"
        elsif Gitlab::Geo.secondary?
          "Geo Secondary Site | #{Gitlab::Geo.current_node.name}"
        elsif Gitlab::Geo.enabled?
          raise "Geo enabled but I don't know what site I am a part of"
        else
          raise "Geo not enabled"
        end
      end
    end
  end
end
