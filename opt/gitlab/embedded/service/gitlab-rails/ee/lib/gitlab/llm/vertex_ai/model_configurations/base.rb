# frozen_string_literal: true

module Gitlab
  module Llm
    module VertexAi
      module ModelConfigurations
        class Base
          MissingConfigurationError = Class.new(StandardError)

          def initialize(user:, options: {})
            @user = user
            @options = options
          end

          def url
            raise MissingConfigurationError if host.blank? || vertex_ai_project.blank?

            "#{Gitlab::AiGateway.url}/v1/proxy/vertex-ai" \
              "/v1/projects/#{vertex_ai_project}/locations/#{vertex_ai_location}" \
              "/publishers/google/models/#{model}:predict"
          end

          def host
            vertex_ai_host || "us-central1-aiplatform.googleapis.com"
          end

          def as_json(_opts = nil)
            {
              vertex_ai_host: host,
              vertex_ai_project: vertex_ai_project,
              model: model
            }
          end

          private

          attr_reader :user, :options

          def vertex_ai_host
            URI.parse(Gitlab::AiGateway.url).host
          end

          def vertex_ai_project
            "PROJECT" # AI Gateway replaces the project hence setting an arbitrary value.
          end

          def vertex_ai_location
            "LOCATION" # AI Gateway replaces the location hence setting an arbitrary value.
          end

          def settings
            @settings ||= Gitlab::CurrentSettings.current_application_settings
          end

          def model
            self.class::NAME
          end
        end
      end
    end
  end
end
