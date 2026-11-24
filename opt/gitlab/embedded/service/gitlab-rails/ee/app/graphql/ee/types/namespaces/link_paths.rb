# frozen_string_literal: true

module EE
  module Types
    module Namespaces
      module LinkPaths
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          field :epics_list,
            GraphQL::Types::String,
            null: true,
            description: 'Namespace epics_list.',
            fallback_value: nil

          field :group_issues,
            GraphQL::Types::String,
            null: true,
            description: 'Namespace group_issues.',
            fallback_value: nil

          field :labels_fetch,
            GraphQL::Types::String,
            null: true,
            description: 'Namespace labels_fetch.',
            fallback_value: nil

          field :issues_settings,
            GraphQL::Types::String,
            null: true,
            description: 'Namespace issues settings path.'

          field :epics_list_path,
            GraphQL::Types::String,
            null: true,
            description: 'Path to the epics list for the namespace.',
            fallback_value: nil,
            experiment: { milestone: '18.6' }

          def issues_settings
            return unless object&.root_ancestor

            root_group = object.root_ancestor
            return unless root_group.is_a?(Group)

            url_helpers.group_settings_work_items_path(root_group)
          end

          def epics_list_path
            return unless object.is_a?(Group)

            url_helpers.group_epics_path(object)
          end
        end

        override :new_trial_path
        def new_trial_path
          if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
            url_helpers.new_trial_path(namespace_id: group&.id)
          else
            super
          end
        end
      end
    end
  end
end
