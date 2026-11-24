# frozen_string_literal: true

module Gitlab
  module SecurityReportSchemas
    # Holds the configuration of the gem
    class Configuration
      OPTIONS = {
        schemas_path: -> { SecurityReportSchemas.root_path.join("schemas") },
        deprecated_versions: -> { [] },
        schema_project: -> { "gitlab-org/security-products/security-report-schemas" },
        ci_server_host: nil
      }.freeze

      OPTIONS.each do |option, default_value|
        define_method(option) do
          instance_variable_get("@#{option}") || ENV[option.upcase.to_s] || default_value&.call
        end

        attr_writer option
      end

      def initialize
        yield self if block_given?
      end

      def schema_project_url
        "https://gitlab.com/#{schema_project}"
      end

      def schema_repository
        "#{schema_project_url}.git"
      end

      def gitlab_project_url
        "https://gitlab.com/#{gitlab_project}"
      end

      def gitlab_repository
        "#{gitlab_project_url}.git"
      end
    end
  end
end
