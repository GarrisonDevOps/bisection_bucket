# frozen_string_literal: true

module Preloaders
  module Sbom
    class PolicyDismissalsPreloader
      def initialize(dependencies, group)
        @dependencies = dependencies
        @group = group
      end

      def execute
        return if dependencies.empty?

        dismissals_by_component_version_id = load_dismissals_by_component_version_id

        dependencies.each do |occurrence|
          occurrence.policy_dismissals =
            dismissals_by_component_version_id.fetch(occurrence.component_version_id, [])
        end
      end

      private

      attr_reader :dependencies, :group

      def load_dismissals_by_component_version_id
        component_version_ids = dependencies.filter_map(&:component_version_id).uniq
        return {} if component_version_ids.blank?

        uuid_to_component_version_id = ::Sbom::Occurrence
          .for_namespace_and_descendants(group)
          .unarchived
          .filter_by_component_version_ids(component_version_ids)
          .pluck_uuid_and_component_version_id
          .to_h
          .transform_keys(&:to_s)

        return {} if uuid_to_component_version_id.empty?

        dismissals = ::Security::PolicyDismissal
          .for_license_occurrence_uuids(uuid_to_component_version_id.keys)
          .including_merge_request_and_user
          .including_security_policy
          .including_project

        result = Hash.new { |h, k| h[k] = [] }
        dismissals.each do |dismissal|
          matched_component_version_ids = Set.new
          dismissal.license_occurrence_uuids.each do |uuid|
            component_version_id = uuid_to_component_version_id[uuid]
            next unless component_version_id
            next if matched_component_version_ids.include?(component_version_id)

            matched_component_version_ids.add(component_version_id)
            result[component_version_id] << dismissal
          end
        end

        result
      end
    end
  end
end
