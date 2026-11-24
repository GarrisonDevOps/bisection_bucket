# frozen_string_literal: true

class GitlabSubscriptionPolicy < ::BasePolicy # rubocop:disable Gitlab/BoundedContexts, Gitlab/NamespacedClass -- Must match the top-level GitlabSubscription model
  delegate { @subject.namespace }
end
