# frozen_string_literal: true

module Analytics
  module Orbit
    class MemberTurnedOnAlertComponent < ViewComponent::Base
      FEATURE_ID = 'orbit_turned_on_alert'
      DOCS_URL = 'https://docs.gitlab.com/orbit/' # rubocop:disable Gitlab/DocumentationLinks/HardcodedUrl -- Orbit docs are published from the Orbit repository, not doc/

      def initialize(current_user:, root:, source:)
        @current_user = current_user
        @root = root
        @source = source
      end

      private

      attr_reader :current_user, :root, :source

      def render?
        current_user.present? &&
          current_user.human? &&
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
          ::Analytics::KnowledgeGraph.enabled_for?(current_user) &&
          orbit_on_long_enough? &&
          reporter_or_higher? &&
          !dismissed? &&
          billed_for_orbit?
      end

      def orbit_on_long_enough?
        enabled_namespace = root.knowledge_graph_enabled_namespace

        enabled_namespace.present? &&
          enabled_namespace.created_at <= ::Analytics::Orbit::MemberNotifications::DELAY.ago
      end

      def reporter_or_higher?
        source.member?(current_user, ::Gitlab::Access::REPORTER)
      end

      def billed_for_orbit?
        ::Analytics::Orbit::Billing.reject_gated_root_ids_without_access([root.id]).any?
      end

      def dismissed?
        current_user.dismissed_callout_for_group?(feature_name: FEATURE_ID, group: root)
      end

      def title
        s_('Orbit|GitLab Orbit is now available to your group')
      end

      def body_text
        s_('Orbit|Ask questions that span projects with GitLab Duo or your own agents.')
      end
    end
  end
end
