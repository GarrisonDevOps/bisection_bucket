# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    class BaseCheck
      include Gitlab::ClassAttributes
      include Gitlab::Utils::StrongMemoize

      def self.execute(project)
        new(project).execute
      end

      def self.enqueue(project)
        instance = new(project)

        if synchronous?
          instance.execute
        else
          instance.execute_async
        end
      end

      def self.synchronous_check!
        set_class_attribute(:synchronous_check, true)
      end

      def self.synchronous?
        !!get_class_attribute(:synchronous_check)
      end

      def initialize(project)
        @project = project
      end

      attr_reader :project

      def execute
        fix! unless consistent?
      end

      def consistent?
        # Check while fixing by default
        false
      end

      def fix!
        raise 'Must implement #fix!'
      end

      def execute_async
        Vulnerabilities::ConsistencyCheckWorker.perform_async(check_class, project.id)
      end

      def check_class
        self.class.name
      end

      def log(message, **additional_fields)
        ::Gitlab::AppLogger.info(
          message: message,
          project: project.full_path,
          project_id: project.id,
          namespace_id: project.namespace.id,
          job: check_class,
          **additional_fields
        )
      end
    end
  end
end
