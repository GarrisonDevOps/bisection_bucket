# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class ProbeResult
        attr_reader :name, :success, :message, :details, :errors

        def initialize(name, success, message, details = [], errors = [])
          @name = name
          @success = success
          @message = message
          @details = details
          @errors = errors
        end

        def success?
          !!@success
        end
      end
    end
  end
end
