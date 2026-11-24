# frozen_string_literal: true

module ComplianceManagement
  module Projects
    class ViolationDetectionService
      attr_reader :project, :control, :audit_event

      def initialize(project, control, audit_event)
        @project = project
        @control = control
        @audit_event = audit_event
      end

      def execute
        detector = find_detector

        detector.detect_violations
      end

      private

      def find_detector
        detector_class_name = "ComplianceManagement::Projects::ViolationDetectors::#{control.name.camelize}Detector"

        unless Object.const_defined?(detector_class_name)
          raise "Violation detector not found: #{detector_class_name}. " \
            "Please create the detector class or remove '#{control.name}' from the audit event configuration."
        end

        detector_class = detector_class_name.constantize
        detector_class.new(project, control, audit_event)
      end
    end
  end
end
