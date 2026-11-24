# frozen_string_literal: true

require 'declarative_policy'

# This module speeds up class resolution by caching it.
#
# See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/119924
# See https://gitlab.com/gitlab-org/ruby/gems/declarative-policy/-/issues/30
module ClassForClassCache
  def self.prepended(base)
    class << base
      attr_accessor :class_for_class_cache
    end

    base.class_for_class_cache = {}
    base.singleton_class.prepend(SingletonClassMethods)
  end

  module SingletonClassMethods
    def class_for_class(subject_class)
      class_for_class_cache.fetch(subject_class) do
        class_for_class_cache[subject_class] = super
      end
    end
  end
end

# Lets a subject define its own policy cache key when its `id` isn't unique across records.
# TODO: remove once declarative_policy supports this natively: https://gitlab.com/gitlab-org/gitlab/-/work_items/635326
module SubjectCacheKey
  def subject_key(subject)
    return subject.declarative_policy_subject_key if subject.respond_to?(:declarative_policy_subject_key)

    super
  end
end

DeclarativePolicy.configure do
  named_policy :global, ::GlobalPolicy
  named_policy :instance_admin_area, ::Authz::InstanceAdminAreaPolicy
  named_policy :organization_admin_area, ::Authz::OrganizationAdminAreaPolicy
end

DeclarativePolicy.prepend(ClassForClassCache)
DeclarativePolicy::Cache.singleton_class.prepend(SubjectCacheKey)
