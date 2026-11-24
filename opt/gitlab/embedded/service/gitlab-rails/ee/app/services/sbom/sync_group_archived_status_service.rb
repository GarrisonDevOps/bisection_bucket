# frozen_string_literal: true

module Sbom
  class SyncGroupArchivedStatusService
    include Gitlab::Utils::StrongMemoize

    OCCURRENCE_BATCH_SIZE = 1_000
    OCCURRENCE_SLICE_SIZE = 100
    REF_BATCH_SIZE = 100

    def initialize(group_id)
      @group_id = group_id
    end

    def execute
      return unless group

      each_batch_in_group do |batch|
        # The scope only matches unarchived occurrences, so the ids must be read before the update.
        occurrence_ids = batch.pluck_primary_key if reindex_refs?

        batch.update_all(archived: group.self_or_ancestors_archived?)

        reindex_occurrence_refs(occurrence_ids) if reindex_refs?
      end
    end

    private

    def reindex_refs?
      ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?
    end
    strong_memoize_attr :reindex_refs?

    # Sliced because every boundary query re-plans the whole id list, and refs per occurrence are
    # unbounded.
    def reindex_occurrence_refs(occurrence_ids)
      occurrence_ids.each_slice(OCCURRENCE_SLICE_SIZE) do |ids|
        ::Sbom::OccurrenceRef.by_occurrence(ids).each_batch(of: REF_BATCH_SIZE) do |batch|
          ::Sbom::BulkEsOperationService.new(batch).execute
        end
      end
    end

    def each_batch_in_group
      scope = ::Sbom::Occurrence
        .for_namespace_and_descendants(group)
        .unarchived
        .order_traversal_ids_asc

      iterator = ::Gitlab::Pagination::Keyset::Iterator.new(scope: scope)
      iterator.each_batch(of: OCCURRENCE_BATCH_SIZE) do |batch|
        yield batch
      end
    end

    attr_reader :group_id

    def group
      @group ||= Group.find_by_id(group_id)
    end
  end
end
