# frozen_string_literal: true

module Organizations
  module Transfer
    class SbomService
      include Organizations::Transfer::Concerns::MissingRecordHandling

      BATCH_SIZE = ApplicationRecord::MAX_PLUCK
      OCCURRENCE_BATCH_SIZE = 250
      OCCURRENCE_SLICE_SIZE = 100
      REF_BATCH_SIZE = 100

      def initialize(group:, old_organization:, new_organization:)
        @group = group
        @old_organization = old_organization
        @new_organization = new_organization
      end

      def execute
        error = missing_record_error
        return error if error

        each_project_batch do |project_ids|
          transfer_project_occurrences(project_ids)
        end

        ServiceResponse.success
      end

      private

      attr_reader :group, :old_organization, :new_organization

      def each_project_batch
        projects.each_batch(of: BATCH_SIZE) do |batch|
          yield batch.limit(BATCH_SIZE).pluck_primary_key
        end
      end

      def projects
        ::Project.in_namespace(group.self_and_descendant_ids(skope: ::Namespace))
      end

      def transfer_project_occurrences(project_ids)
        # A single `project_id = ?` scope lets the boundary query use the project index.
        project_ids.each do |project_id|
          ::Sbom::Occurrence.by_project_ids(project_id).each_batch(of: OCCURRENCE_BATCH_SIZE) do |batch|
            occurrences = batch.limit(OCCURRENCE_BATCH_SIZE).select(
              :id, :component_id, :component_version_id, :source_package_id, :source_id
            ).to_a

            # One transaction per batch keeps transactions short; a retry picks up where a failure left off.
            ::SecApplicationRecord.transaction { transfer_occurrence_batch(occurrences) }

            reindex_occurrence_refs(occurrences.map(&:id))
          end
        end
      end

      # Tracked after the transaction so the bulk cron cannot serialize uncommitted ids. Sliced
      # because every boundary query re-plans the whole id list.
      def reindex_occurrence_refs(occurrence_ids)
        return unless ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?

        occurrence_ids.each_slice(OCCURRENCE_SLICE_SIZE) do |ids|
          ::Sbom::OccurrenceRef.by_occurrence(ids).each_batch(of: REF_BATCH_SIZE) do |batch|
            ::Sbom::BulkEsOperationService.new(batch).execute
          end
        end
      end

      def transfer_occurrence_batch(occurrences)
        components = replicate_lookup(
          ::Sbom::Component, occurrences.map(&:component_id),
          natural_keys: %w[name purl_type component_type],
          unique_by: 'idx_sbom_components_on_name_purl_type_component_type_and_org_id'
        )

        component_versions = replicate_lookup(
          ::Sbom::ComponentVersion, occurrences.map(&:component_version_id),
          natural_keys: %w[version source_package_name],
          unique_by: 'idx_sbom_comp_versions_on_comp_id_version_and_org_id',
          remap: { 'component_id' => components }
        )

        source_packages = replicate_lookup(
          ::Sbom::SourcePackage, occurrences.map(&:source_package_id),
          natural_keys: %w[name purl_type],
          unique_by: 'index_sbom_source_packages_on_name_and_purl_type_and_org_id'
        )

        sources = replicate_lookup(
          ::Sbom::Source, occurrences.map(&:source_id),
          natural_keys: %w[source_type source],
          unique_by: 'index_sbom_sources_on_source_type_and_source_and_org_id'
        )

        update_occurrences(occurrences,
          component_id: components,
          component_version_id: component_versions,
          source_package_id: source_packages,
          source_id: sources
        )
      end

      # Copies lookup rows from the old organization into the new one (skipping duplicates),
      # then returns a mapping of { old_id => new_id } so occurrence FKs can be repointed.
      # rubocop:disable CodeReuse/ActiveRecord -- Natural-key lookups are generic over the Sbom models.
      def replicate_lookup(model, ids, natural_keys:, unique_by:, remap: {})
        ids = ids.compact.uniq
        records = model.where(id: ids, organization_id: organization_ids).to_a
        old_records = records.select { |r| r.organization_id == old_organization.id }

        if old_records.any?
          rows = old_records.map do |r|
            attrs = r.attributes.slice(*natural_keys).merge('organization_id' => new_organization.id)
            remap.each { |col, mapping| attrs[col] = mapping.fetch(r.attributes[col]) }
            attrs
          end

          model.insert_all(rows, unique_by: unique_by, returning: false)
        end

        target_filter = natural_keys.index_with { |col| old_records.map { |r| r.attributes[col] } }
        remap.each { |col, mapping| target_filter[col] = old_records.map { |r| mapping.fetch(r.attributes[col]) } }
        target_filter['organization_id'] = new_organization.id

        targets = model.where(target_filter).index_by { |r| natural_key_values(r, natural_keys, remap) }

        records.to_h do |r|
          if r.organization_id == new_organization.id
            [r.id, r.id]
          else
            [r.id, targets.fetch(natural_key_values(r, natural_keys, remap)).id]
          end
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def update_occurrences(occurrences, mappings)
        table = ::Sbom::Occurrence.arel_table

        assignments = mappings.to_h do |col, mapping|
          expr = occurrences.each_with_object(Arel::Nodes::Case.new(table[:id])) do |o, node|
            old_val = o.read_attribute(col)
            node.when(o.id).then(old_val ? mapping.fetch(old_val) : nil)
          end
          [col, expr.else(table[col])]
        end

        ::Sbom::Occurrence.id_in(occurrences.map(&:id)).update_all(assignments)
      end

      def natural_key_values(record, natural_keys, remap)
        key = natural_keys.map { |col| record.attributes[col] }
        remap.each do |col, mapping|
          val = record.attributes[col]
          key << mapping.fetch(val, val)
        end
        key
      end

      def organization_ids
        [old_organization.id, new_organization.id]
      end
    end
  end
end
