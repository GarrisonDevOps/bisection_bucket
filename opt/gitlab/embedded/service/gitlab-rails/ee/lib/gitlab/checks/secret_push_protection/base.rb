# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class Base
        include ::Gitlab::Loggable
        include ::Gitlab::Utils::StrongMemoize

        attr_reader :project, :changes_access

        def initialize(project:, changes_access:)
          @project = project
          @changes_access = changes_access
        end

        def audit_logger
          AuditLogger.new(
            project: project,
            changes_access: changes_access
          )
        end
        strong_memoize_attr :audit_logger

        def secret_detection_logger
          ::Gitlab::SecretDetectionLogger.build
        end
        strong_memoize_attr :secret_detection_logger
      end
    end
  end
end
