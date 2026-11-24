# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class UpdateProjectAncestorsStatisticsService < BaseUpdateAncestorsService
      def self.execute(project)
        new(project).execute
      end

      private

      def vulnerable_namespace
        vulnerable.namespace
      end

      def vulnerable_statistics
        @vulnerable_statistics ||= Vulnerabilities::Statistic.for_project(vulnerable)[0]
      end
    end
  end
end
