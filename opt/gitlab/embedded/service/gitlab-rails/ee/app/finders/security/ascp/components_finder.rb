# frozen_string_literal: true

module Security
  module Ascp
    class ComponentsFinder
      def initialize(project:, params: {})
        @project = project
        @params = params
      end

      def execute
        components = project.security_ascp_components
        components = components.by_title(params[:title]) if params[:title].present?
        components = components.by_sub_directory(params[:sub_directory]) if params[:sub_directory].present?
        components.ordered
      end

      private

      attr_reader :project, :params
    end
  end
end
