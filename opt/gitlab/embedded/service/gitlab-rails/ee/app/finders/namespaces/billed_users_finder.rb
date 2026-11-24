# frozen_string_literal: true

module Namespaces
  class BilledUsersFinder
    CROSS_JOIN_ISSUE_URL = "https://gitlab.com/gitlab-org/gitlab/-/issues/417464"

    def initialize(group, exclude_guests: false)
      @group = group
      @exclude_guests = exclude_guests
      @ids = { user_ids: Set.new }
    end

    def execute
      METHOD_KEY_MAP.each do |method_name, ids_hash_key|
        calculate_user_ids(method_name, ids_hash_key)
      end

      ids
    end

    private

    attr_reader :group, :ids

    METHOD_KEY_MAP = {
      billed_group_users: :group_member_user_ids,
      billed_project_users: :project_member_user_ids,
      billed_shared_group_users: :shared_group_user_ids,
      billed_invited_group_to_project_users: :shared_project_user_ids
    }.freeze

    def calculate_user_ids(method_name, hash_key)
      user_ids = fetch_user_ids(method_name)

      @ids[hash_key] = user_ids
      @ids[:user_ids].merge(user_ids)
    end

    def fetch_user_ids(method_name)
      scope = group.public_send(method_name, exclude_guests: @exclude_guests) # rubocop:disable GitlabSecurity/PublicSend -- No scope of user input to be passed to this method

      scope = yield(scope) if block_given?

      scope = scope.allow_cross_joins_across_databases(url: CROSS_JOIN_ISSUE_URL)
      scope.pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- ids are relevant only for these records
    end
  end
end
