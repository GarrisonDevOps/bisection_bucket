# frozen_string_literal: true

module Ai
  module ActiveContext
    module Concerns
      module Loggable
        include Gitlab::Loggable

        # Redirect to the LabKit-compliant variant which emits class_name instead
        # of the deprecated class field.
        # TODO: Remove once Gitlab::Loggable#build_structured_payload is updated globally.
        # https://gitlab.com/groups/gitlab-org/quality/-/epics/309
        alias_method :build_structured_payload, :build_structured_payload_labkit

        private

        def logger
          @logger ||= ::ActiveContext::Config.logger
        end
      end
    end
  end
end
