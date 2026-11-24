# frozen_string_literal: true

module Types
  module Sbom
    class DependencyAggregationType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name 'DependencyAggregation'
      description 'A software dependency aggregation used by a group'

      implements Types::Sbom::DependencyInterface

      field :occurrence_count, GraphQL::Types::Int,
        null: false,
        description: 'Number of occurrences of the dependency across projects.'

      field :project_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.2' },
        description: 'Number of projects that use the dependency.'

      # Mirrors the REST serializer (ee/app/serializers/dependency_entity.rb).
      # AggregationsFinder returns an object with a project_count attribute, but the
      # object may be a plain Sbom::Occurrence (when the project_ids filter is used)
      # which has no project_count attribute, so we fall back to 1.
      def project_count
        object.respond_to?(:project_count) ? object.project_count : 1
      end

      def licenses
        return [] unless object.licenses.present?

        apply_group_license_overrides(object.licenses)
      end

      # Mirrors the REST serializer (ee/app/serializers/dependency_entity.rb)
      # AggregationFinder returns an object with occurrence_count attribute
      # but the object may be a plain `Sbom::Occurrence` (when project_ids filter is used)
      # which does not have an `occurrence_count` attribute, so we fall back to 1.
      def occurrence_count
        object.respond_to?(:occurrence_count) ? object.occurrence_count : 1
      end

      private

      def apply_group_license_overrides(licenses)
        group = context[:group]
        return licenses unless group &&
          ::Security::LicenseOverrideApplicator.experiment_enabled_for_group?(group)

        applicator = group_license_override_applicator
        return licenses unless applicator.overrides?

        dep_purl = aggregation_purl
        return licenses unless dep_purl

        applicator.apply(licenses, purl: dep_purl)
      end

      def aggregation_purl
        return unless object.purl_type.present?

        base = "pkg:#{object.purl_type}/#{object.component_name}"
        version = object.version
        version.present? ? "#{base}@#{version}" : base
      end

      def group_license_override_applicator
        context[:security_group_license_override_applicator] ||=
          ::Security::LicenseOverrideApplicator.new_for_group(context[:group])
      end
    end
  end
end
