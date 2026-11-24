# frozen_string_literal: true

module Groups
  # Service class for counting and caching the number of open merge requests of a group.
  class MergeRequestsCountService < Groups::CountService
    extend ::Gitlab::Utils::Override

    override :initialize
    def initialize(*args, fast_timeout: false)
      super(*args)

      @fast_timeout = fast_timeout
    end

    private

    override :uncached_count
    def uncached_count
      return super unless @fast_timeout

      ApplicationRecord.with_fast_read_statement_timeout do # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- this is called outside a transaction
        super
      end
    end

    def cache_key_name
      'open_merge_requests_count'
    end

    def relation_for_count
      MergeRequestsFinder
      .new(user, group_id: group.id, state: 'opened', non_archived: true, include_subgroups: true)
      .execute
    end

    def issuable_key
      'open_merge_requests'
    end
  end
end
