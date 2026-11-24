# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class WidgetPresenter < Gitlab::View::Presenter::Simple
      def initialize(namespace, user:)
        @namespace = namespace
        @user = user
      end

      delegate :attributes, to: :presenter

      private

      attr_reader :user, :namespace

      def presenter
        if authorized_self_managed?
          SelfManaged::StatusWidgetPresenter.new(::License.current, user: user) # rubocop:disable CodeReuse/Presenter -- we use it in this coordinator class
        elsif authorized_gitlab_com?
          GitlabCom::StatusWidgetPresenter.new(namespace, user: user) # rubocop:disable CodeReuse/Presenter -- we use it in this coordinator class
        else
          {}.tap { |h| h.define_singleton_method(:attributes) { self } }
        end
      end

      def authorized_self_managed?
        !::Gitlab::Saas.feature_available?(:subscriptions_trials) && Ability.allowed?(user, :admin_all_resources)
      end

      def authorized_gitlab_com?
        namespace.present? &&
          ::Gitlab::Saas.feature_available?(:subscriptions_trials) &&
          Ability.allowed?(user, :admin_namespace, namespace)
      end
    end
  end
end

# Added for JiHu
# Used in https://jihulab.com/gitlab-cn/gitlab/-/blob/main-jh/jh/app/presenters/jh/gitlab_subscriptions/trials/widget_presenter.rb
GitlabSubscriptions::Trials::WidgetPresenter.prepend_mod
