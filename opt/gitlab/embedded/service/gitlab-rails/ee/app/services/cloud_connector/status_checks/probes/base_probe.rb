# frozen_string_literal: true

require 'active_model'

module CloudConnector
  module StatusChecks
    module Probes
      class BaseProbe
        include ActiveModel::Validations
        include ActiveModel::Validations::Callbacks

        class Details
          delegate :each, :[], :empty?, :to_hash, to: :@messages

          def initialize
            @messages = {}
          end

          def add(attribute, message)
            @messages[attribute] = message
          end
        end

        def execute
          return failure(failure_message) unless valid?

          success(success_message)
        end

        private

        def details
          @details ||= Details.new
        end

        def probe_name
          self.class.name.demodulize.underscore.to_sym
        end

        def success(message)
          create_result(true, message)
        end

        def failure(message)
          create_result(false, message)
        end

        def create_result(success, message)
          ProbeResult.new(probe_name, success, message, details, errors)
        end

        def failure_message
          errors.full_messages.first
        end

        def success_message
          raise NotImplementedError, "#{self.class} must implement #success_message"
        end
      end
    end
  end
end
