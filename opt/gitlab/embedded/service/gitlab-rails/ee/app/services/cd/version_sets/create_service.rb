# frozen_string_literal: true

module Cd
  module VersionSets
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
        @version_ids = Array(@params.delete(:version_ids)).uniq
      end

      def execute
        return empty_versions_error if version_ids.empty?

        versions = load_versions

        return versions_not_found_error if versions.size != version_ids.size
        return duplicate_sources_error if duplicate_sources?(versions)

        version_set = ::Cd::VersionSet.new(
          params.merge(application: parent, organization: organization, created_by: current_user)
        )

        ::Cd::VersionSet.transaction do
          version_set.save!

          ::Cd::VersionSetEntry.bulk_insert!(build_entries(version_set, versions))

          version_set.update_entries_digest!
        end

        ServiceResponse.success(payload: { version_set: version_set })
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(
          message: e.record.errors.full_messages,
          payload: { version_set: version_set }
        )
      rescue ActiveRecord::RecordNotUnique
        ServiceResponse.error(
          message: [_('A version set with the same versions already exists in the application')],
          payload: { version_set: version_set }
        )
      end

      private

      attr_reader :parent, :current_user, :params, :version_ids

      def organization
        @organization ||= parent.organization
      end

      def load_versions
        ::Cd::Version
          .for_application(parent)
          .id_in(version_ids)
          .preload_artifact_source_and_service
          .to_a
      end

      def build_entries(version_set, versions)
        timestamp = Time.current

        versions.map do |version|
          artifact_source = version.artifact_source

          ::Cd::VersionSetEntry.new(
            version_set: version_set,
            version: version,
            artifact_source: artifact_source,
            service: artifact_source.service,
            organization: organization,
            created_at: timestamp,
            updated_at: timestamp
          )
        end
      end

      def duplicate_sources?(versions)
        source_ids = versions.map(&:artifact_source_id)
        source_ids.uniq.size != source_ids.size
      end

      def empty_versions_error
        ServiceResponse.error(message: [_('A version set must contain at least one version')])
      end

      def versions_not_found_error
        ServiceResponse.error(
          message: [_('One or more versions were not found or do not belong to the application')]
        )
      end

      def duplicate_sources_error
        ServiceResponse.error(message: [_('Each artifact source can appear only once in a version set')])
      end
    end
  end
end
