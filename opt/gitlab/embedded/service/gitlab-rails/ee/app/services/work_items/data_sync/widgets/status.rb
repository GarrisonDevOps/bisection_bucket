# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class Status < Base
        include Gitlab::Utils::StrongMemoize

        def after_save
          return unless status_row_allowed?

          ensure_target_lifecycle_connection!
          return unless target_lifecycle

          current_status = target_work_item.build_current_status

          current_status.status = if work_item.state != target_work_item.state
                                    default_status_for_target_work_item_state
                                  else
                                    find_matching_status
                                  end

          current_status.save!
        end

        def post_move_cleanup
          work_item.current_status&.destroy!
        end

        private

        def status_row_allowed?
          ::WorkItems::Statuses::FeatureFlags.write_status_row?(
            target_work_item.work_item_type.base_type, target_root_ancestor
          )
        end

        # A masked type (e.g. epic) needs its real type<->lifecycle row before the
        # CurrentStatus validations run, otherwise custom_status_enabled? is false.
        def ensure_target_lifecycle_connection!
          ::WorkItems::Statuses::Lifecycles::Provider
            .new(target_root_ancestor.id)
            .ensure_connection!(target_work_item.work_item_type)
        end

        def find_matching_status
          lifecycle = work_item.work_item_type.status_lifecycle_for(work_item.resource_parent&.root_ancestor&.id)
          status = work_item.status_with_fallback

          return status if lifecycle == target_lifecycle

          ::WorkItems::Widgets::Statuses::StatusMatcherService.new(status, target_lifecycle).find_fallback
        end

        def default_status_for_target_work_item_state
          if target_work_item.open?
            target_lifecycle.default_open_status
          elsif target_work_item.duplicated?
            target_lifecycle.default_duplicate_status
          else
            target_lifecycle.default_closed_status
          end
        end

        def target_root_ancestor
          target_work_item.resource_parent&.root_ancestor
        end
        strong_memoize_attr :target_root_ancestor

        def target_lifecycle
          target_work_item.work_item_type.status_lifecycle_for(target_root_ancestor&.id)
        end
        strong_memoize_attr :target_lifecycle
      end
    end
  end
end
