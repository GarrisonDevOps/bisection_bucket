# frozen_string_literal: true

module WorkItems
  module TypesFramework
    module Custom
      class TypePolicy < BasePolicy
        delegate { @subject.namespace || @subject.organization }

        condition(:configurable_work_item_types_licensed) do
          if @subject.namespace
            @subject.namespace.licensed_feature_available?(:configurable_work_item_types)
          else
            # rubocop:disable Gitlab/NoCodeCoverageComment -- admin_work_item_lifecycle is not yet implemented at the organization level
            # simplecov:disable
            License.feature_available?(:configurable_work_item_types)
            # simplecov:enable
            # rubocop:enable Gitlab/NoCodeCoverageComment
          end
        end

        rule { ~configurable_work_item_types_licensed }.policy do
          prevent :admin_work_item_lifecycle
        end
      end
    end
  end
end
