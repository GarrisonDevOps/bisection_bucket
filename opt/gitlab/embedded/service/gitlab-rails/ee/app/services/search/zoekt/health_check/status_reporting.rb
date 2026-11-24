# frozen_string_literal: true

module Search
  module Zoekt
    module HealthCheck
      module StatusReporting
        extend ActiveSupport::Concern

        included do
          private

          attr_reader :logger
          attr_accessor :status, :warnings, :errors
        end

        private

        def add_error(message)
          errors << message
          self.status = :unhealthy if status != :unhealthy
        end

        def add_warning(message)
          warnings << message
          self.status = :degraded if status == :healthy
        end

        def log_check(message, color = :white)
          logger.info("  #{colorize(message, color)}")
        end

        def colorize(text, color)
          Rainbow(text).color(color)
        end

        def node_name(node)
          node.metadata['name'] || 'unnamed'
        end
      end
    end
  end
end
