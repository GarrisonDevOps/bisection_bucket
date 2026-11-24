# frozen_string_literal: true

module Namespaces
  class TrialEligibleFinder
    include Gitlab::Utils::StrongMemoize

    EXPIRATION_TIME = 8.hours
    FAILURE_EXPIRATION_TIME = 5.minutes
    FAIL_FAST_REQUEST_OPTIONS = { timeout: 1.second, max_retries: 0 }.freeze

    def initialize(params = {})
      @params = params
    end

    def execute
      namespaces = scope_by_plans.in_specific_plans(eligible_plans)
      return Namespace.none if namespaces.empty?

      build_namespaces_trial_type(namespaces)
      namespaces.id_in(find_eligible_namespace_ids).ordered_by_name
    end

    private

    attr_reader :params, :namespaces_trial_type

    def build_namespaces_trial_type(namespaces)
      @namespaces_trial_type = namespaces.to_h { |namespace| [namespace.id, namespace_trial_type(namespace)] }
    end

    def namespace_ids
      namespaces_trial_type.keys
    end

    def namespace_trial_type(namespace)
      GitlabSubscriptions::Trials.trial_type_for_namespace(namespace)
    end

    def scope_by_plans
      if params[:user] && params[:namespace]
        raise ArgumentError, 'Only User or Namespace can be provided, not both'
      elsif params[:user]
        params[:user].owned_groups
      elsif params[:namespace]
        Namespace.id_in(params[:namespace])
      else
        raise ArgumentError, 'User or Namespace must be provided'
      end
    end

    def no_subscription_plan_name
      # Subscriptions aren't created until needed/looked at
      nil
    end

    def eligible_plans
      [no_subscription_plan_name, *::GitlabSubscriptions::SystemDefined::Plan::PLANS_ELIGIBLE_FOR_TRIAL]
    end

    def find_eligible_namespace_ids
      entries = read_cached_entries

      if namespace_ids.all? { |id| cached_or_recently_failed?(entries, id) }
        cached_eligible_namespace_ids(entries)
      else
        cache_eligible_namespace_ids
      end
    end

    def client
      Gitlab::SubscriptionPortal::Client
    end

    def cache_key(id)
      "namespaces:eligible_trials:#{id}"
    end

    def failure_cache_key(id)
      "namespaces:eligible_trials:failed:#{id}"
    end

    def cache_keys
      namespace_ids.map { |id| cache_key(id) }
    end
    strong_memoize_attr :cache_keys

    # Only fail-fast callers read the failure keys, so other callers treat a recorded failure as a cache miss.
    def read_cached_entries
      keys = cache_keys
      keys += namespace_ids.map { |id| failure_cache_key(id) } if fail_fast?

      Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
        Rails.cache.read_multi(*keys)
      end
    end

    def filter_namespace_ids(id_trials_hash)
      id_trials_hash.filter_map do |id, eligible_trial_types|
        id if namespaces_trial_type[id.to_i].in?(eligible_trial_types)
      end
    end

    def cached_or_recently_failed?(entries, id)
      entries.key?(cache_key(id)) || entries.key?(failure_cache_key(id))
    end

    def cached_eligible_namespace_ids(entries)
      filter_namespace_ids(namespace_ids.index_with { |id| entries.fetch(cache_key(id), []) })
    end

    def eligible_trials_request
      response = client.namespace_eligible_trials(namespace_ids: namespace_ids, **request_options)

      if response[:success]
        response.dig(:data, :namespaces)
      else
        Gitlab::AppLogger.warn(
          class: self.class.name,
          message: 'Unable to fetch eligible trials from GitLab Customers App',
          error_message: response.dig(:data, :errors)
        )

        cache_failed_request

        {}
      end
    end

    def request_options
      fail_fast? ? FAIL_FAST_REQUEST_OPTIONS : {}
    end

    def cache_failed_request
      return unless fail_fast?

      Rails.cache.write_multi(
        namespace_ids.to_h { |id| [failure_cache_key(id), true] },
        expires_in: FAILURE_EXPIRATION_TIME
      )
    end

    def fail_fast?
      !!params[:fail_fast] && Feature.enabled?(:fail_fast_cdot_trial_requests, Feature.current_request)
    end
    strong_memoize_attr :fail_fast?

    def cache_eligible_namespace_ids
      response_data = eligible_trials_request
      return [] if response_data.blank?

      Rails.cache.write_multi(
        response_data.transform_keys { |id| cache_key(id) },
        expires_in: EXPIRATION_TIME
      )

      filter_namespace_ids(response_data)
    end
  end
end
