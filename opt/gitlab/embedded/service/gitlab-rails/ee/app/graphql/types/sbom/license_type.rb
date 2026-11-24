# frozen_string_literal: true

module Types
  module Sbom
    # Authorization checks are implemented on the parent object.
    class LicenseType < BaseObject # rubocop:disable Graphql/AuthorizeTypes
      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the license.'

      field :url, GraphQL::Types::String,
        null: true, description: 'License URL in relation to SPDX.'

      field :spdx_identifier, GraphQL::Types::String,
        null: true, description: 'Name of the SPDX identifier.'

      field :policy_violations, [::Types::Security::PolicyDismissalType],
        null: true,
        description: 'Policy dismissals associated with the license for the dependency.'

      def policy_violations
        license_name = object['name']
        occurrence_uuid = object['occurrence_uuid']
        project = object['project_id']

        return [] unless license_name && occurrence_uuid && project

        BatchLoader::GraphQL.for([occurrence_uuid, license_name]).batch(default_value: []) do |license_keys, loader|
          occurrence_uuids = license_keys.map(&:first).uniq

          all_dismissals = fetch_dismissals_for_occurrences(occurrence_uuids, project)

          distribute_dismissals_to_licenses(license_keys, all_dismissals, loader)
        end
      end

      private

      def fetch_dismissals_for_occurrences(occurrence_uuids, project_id)
        ::Security::PolicyDismissal.for_projects(project_id)
          .for_license_occurrence_uuids(occurrence_uuids)
          .including_security_policy
      end

      def distribute_dismissals_to_licenses(license_keys, all_dismissals, loader)
        all_dismissals.each do |dismissal|
          dismissal.license_occurrence_uuids.each do |occurrence_uuid|
            matching_license_keys = license_keys.select { |uuid, _name| uuid == occurrence_uuid }

            matching_license_keys.each do |uuid, license_name|
              next unless dismissal_applies_to_license?(dismissal, license_name)

              loader.call([uuid, license_name]) { |dismissals| dismissals << dismissal }
            end
          end
        end
      end

      def dismissal_applies_to_license?(dismissal, license_name)
        return false if dismissal.licenses.blank?
        return false if license_name.blank?

        dismissal.licenses.key?(license_name)
      end
    end
  end
end
