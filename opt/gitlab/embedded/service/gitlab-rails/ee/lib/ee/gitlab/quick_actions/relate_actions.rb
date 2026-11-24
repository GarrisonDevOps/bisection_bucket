# frozen_string_literal: true

module EE
  module Gitlab
    module QuickActions
      module RelateActions
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern
        include ::Gitlab::QuickActions::Dsl

        included do
          desc { _('Link items blocked by this item') }
          explanation do |items|
            format(
              _("Set this %{item_type} as blocking %{target}."),
              item_type: dependency_service.type_name,
              target: dependency_service.format_refs(items)
            )
          end
          execution_message do |items|
            format(
              _("Added %{target} as a linked item blocked by this %{item_type}."),
              item_type: dependency_service.type_name,
              target: dependency_service.format_refs(items)
            )
          end
          params { dependency_service.param_hint }
          types Issue, MergeRequest
          condition { dependency_service.can_block? }
          parse_params { |params| dependency_service.parse_params(params) }
          command :blocks do |items|
            dependency_service.create_link(items, link_type: 'blocks')
          end

          desc { _('Link items blocking this item') }
          explanation do |items|
            format(
              _("Set this %{item_type} as blocked by %{target}."),
              item_type: dependency_service.type_name,
              target: dependency_service.format_refs(items)
            )
          end
          execution_message do |items|
            format(
              _("Added %{target} as a linked item blocking this %{item_type}."),
              item_type: dependency_service.type_name,
              target: dependency_service.format_refs(items)
            )
          end
          params { dependency_service.param_hint }
          types Issue, MergeRequest
          condition { dependency_service.can_block? }
          parse_params { |params| dependency_service.parse_params(params) }
          command :blocked_by do |items|
            dependency_service.create_link(items, link_type: 'is_blocked_by')
          end
        end

        private

        override :dependency_service
        def dependency_service
          @dependency_service ||= if quick_action_target.is_a?(MergeRequest)
                                    ::MergeRequests::QuickActions::DependencyService.new(
                                      quick_action_target, current_user, project
                                    )
                                  else
                                    super
                                  end
        end
      end
    end
  end
end
