# frozen_string_literal: true

module GitlabSubscriptions
  class CurrentActivePlansForUserFinder
    include Gitlab::Utils::StrongMemoize

    def initialize(user)
      @user = user
    end

    def execute
      return [] if user.blank?

      uids = GitlabSubscription.with(members_cte.to_arel) # rubocop:disable CodeReuse/ActiveRecord -- specific to this finder
          .by_hosted_plan_name_uids(
            ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(Plan::CURRENT_ACTIVE_PLANS)
          )
          .namespace_id_in(members_scope.select(:source_id))
          .distinct # rubocop:disable CodeReuse/ActiveRecord -- specific to this finder
          # For pluck use, fits here due to distinct and helps keep all the current logic contained
          .limit(Plan::CURRENT_ACTIVE_PLANS.size)
          .pluck(:hosted_plan_name_uid) # rubocop:disable CodeReuse/ActiveRecord -- specific to this finder

      ::GitlabSubscriptions::SystemDefined::Plan.where(id: uids) # rubocop:disable CodeReuse/ActiveRecord -- this is a fixed model
    end

    private

    attr_reader :user

    def members_scope
      Member.from(members_cte.table) # rubocop:disable CodeReuse/ActiveRecord -- specific to this finder
    end

    def members_cte
      query = GroupMember
                .non_request
                .non_minimal_access
                .with_user(user)
                .select(:source_id)

      Gitlab::SQL::CTE.new(:members, query, materialized: true)
    end
    strong_memoize_attr :members_cte
  end
end
