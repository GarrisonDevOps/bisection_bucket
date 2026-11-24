# frozen_string_literal: true

module Search
  module Elastic
    module Sorts
      class WorkItem < Base
        # Sort keys that read a field the index only populates once an advanced search migration has
        # finished. Adding `title.keyword` to the mapping does not populate it for documents already
        # indexed, and Elasticsearch answers a sort on an unpopulated field with a 200 and the
        # documents in tie-breaker order -- so the key has to stay unavailable until the backfill
        # completes, or the sort silently returns ID order.
        MIGRATION_GATED_SORT_KEYS = {
          title_asc: :backfill_title_keyword_in_work_items,
          title_desc: :backfill_title_keyword_in_work_items
        }.freeze

        SORT_MAPPINGS = Base::SORT_MAPPINGS.merge(
          popularity_asc: { upvotes: { order: 'asc' } },
          popularity_desc: { upvotes: { order: 'desc' } },
          milestone_due_asc: { milestone_due_date: { order: 'asc' } },
          milestone_due_desc: { milestone_due_date: { order: 'desc' } },
          weight_asc: { weight: { order: 'asc' } },
          weight_desc: { weight: { order: 'desc' } },
          health_status_asc: { health_status: { order: 'asc' } },
          health_status_desc: { health_status: { order: 'desc' } },
          closed_at_asc: { closed_at: { order: 'asc' } },
          closed_at_desc: { closed_at: { order: 'desc' } },
          due_date_asc: { due_date: { order: 'asc' } },
          due_date_desc: { due_date: { order: 'desc' } },
          title_asc: { 'title.keyword': { order: 'asc' }, id: { order: 'desc' } },
          title_desc: { 'title.keyword': { order: 'desc' }, id: { order: 'desc' } }
        ).freeze
      end
    end
  end
end
