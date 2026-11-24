# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ProfileBasedUpdateService < BaseUpdateService
      private

      def supported?
        PROFILE_UPDATE_TYPES.include?(analyzer_type)
      end

      def analyzers_statuses
        @analyzers_statuses ||= projects.each_with_object({}) do |project, memo|
          existing_status = find_existing_status(project)
          next if existing_status&.build_id.present? # Pipeline-based value. Don't override with profile-based value.

          new_status = has_applicable_profile?(project) ? :success : :not_configured
          next if existing_status.nil? && new_status == :not_configured
          next if existing_status&.status&.to_sym == new_status

          memo[project] = {
            analyzer_type => build_analyzer_status_hash(project, analyzer_type, new_status)
          }
        end
      end

      def find_existing_status(project)
        project.analyzer_statuses.find { |s| s.analyzer_type.to_sym == analyzer_type }
      end
    end
  end
end
