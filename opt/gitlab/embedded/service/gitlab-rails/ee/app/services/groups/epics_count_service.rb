# frozen_string_literal: true

module Groups
  class EpicsCountService < Groups::CountService
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
      'open_epics_count'
    end

    def relation_for_count
      EpicsFinder
        .new(user, group_id: group.id, state: 'opened')
        .execute(skip_visibility_check: true)
    end

    def issuable_key
      'open_epics'
    end
  end
end
