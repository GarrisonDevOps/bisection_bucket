# frozen_string_literal: true

module API
  module Helpers
    module WorkItems
      # Active authorization checks for the work item REST endpoints: the feature flag gate and the
      # :read_work_item check. Both go away with the work_item_rest_api flag
      # (rollout: gitlab-org/gitlab#588874).
      #
      # The development sub-endpoints deliberately authorize per resource type (MergeRequestsFinder in
      # SQL, bulk Ability helpers, or the source service) rather than through a shared row filter here.
      module Authorization
        def check_work_item_rest_api_feature_flag!
          return if Feature.enabled?(:work_item_rest_api, current_user)

          # Experiment-stage endpoints must 404 (not 403) while the flag is off, so the response does
          # not disclose that the endpoint exists. See doc/development/api_styleguide.md.
          not_found!
        end

        # Invariant prologue for every work-item-scoped read path, so the feature flag gate and the
        # authorization check can't drift apart between the endpoints that need both. A denied read is a
        # 404 like the show endpoint, so the response does not confirm that the work item exists.
        def authorize_work_item_feature!(work_item)
          check_work_item_rest_api_feature_flag!
          not_found!('Work Item') unless can?(current_user, :read_work_item, work_item)
        end
      end
    end
  end
end
