# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class UpdateGroupAncestorsStatisticsService < BaseUpdateAncestorsService
      def self.execute(group)
        new(group).execute
      end

      private

      def vulnerable_namespace
        vulnerable
      end

      def vulnerable_statistics
        @vulnerable_statistics ||= Vulnerabilities::NamespaceStatistic.by_namespace(vulnerable)[0]
      end
    end
  end
end
