# frozen_string_literal: true

module Namespaces
  module Pipelines
    module Alerts
      class SharedRunnersMinutesLimitAlertComponent < ViewComponent::Base
        include ActionView::Helpers::NumberHelper
        include ButtonHelper
        include NamespacesHelper
        include GitlabRoutingHelper

        # @param [Project] project
        # @param [Namespace] namespace
        # @param [User] current_user
        # @param [String] classes
        # @param [Boolean] usage_quotas_link_hidden
        def initialize(project:, namespace:, current_user:, classes:, usage_quotas_link_hidden: false)
          @notification = ::Ci::Minutes::Notification.new(project, namespace)
          @namespace = @notification.namespace
          @usage_quotas_link_hidden = usage_quotas_link_hidden
          @classes = classes
          @current_user = current_user
        end

        private

        attr_reader :namespace, :notification, :usage_quotas_link_hidden, :classes

        def render?
          notification.show_callout?(@current_user)
        end

        def text
          contextual_map.dig(notification.stage, :text)
        end

        def variant
          contextual_map.dig(notification.stage, :style)
        end

        def callout_data
          if namespace.user_namespace?
            return {
              feature_id: notification.callout_feature_id,
              dismiss_endpoint: Rails.application.routes.url_helpers.callouts_path
            }
          end

          {
            feature_id: notification.callout_feature_id,
            dismiss_endpoint: Rails.application.routes.url_helpers.group_callouts_path,
            group_id: namespace.root_ancestor.id
          }
        end

        def contextual_map
          {
            warning: {
              style: :warning,
              text: threshold_message
            },
            danger: {
              style: :danger,
              text: threshold_message
            },
            exceeded: {
              style: :danger,
              text: exceeded_message
            }
          }
        end

        def exceeded_message
          Kernel.format(
            s_(
              "Pipelines|The %{namespace_name} namespace has reached its shared runner compute minutes quota. " \
                "To run new jobs and pipelines in this namespace's projects, buy additional compute minutes."
            ),
            namespace_name: namespace.name
          )
        end

        def threshold_message
          Kernel.format(
            s_(
              "Pipelines|The %{namespace_name} namespace has %{current_balance} / %{total} " \
                "(%{percentage}%%) shared runner compute minutes remaining. When all compute minutes " \
                "are used up, no new jobs or pipelines will run in this namespace's projects."
            ),
            namespace_name: namespace.name,
            current_balance: number_with_delimiter(notification.current_balance),
            total: number_with_delimiter(notification.total),
            percentage: notification.percentage.round
          )
        end
      end
    end
  end
end
