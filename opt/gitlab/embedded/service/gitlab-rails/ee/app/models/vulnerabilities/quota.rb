# frozen_string_literal: true

module Vulnerabilities
  class Quota
    CRITICAL_QUOTA_THRESHOLD = 95

    def initialize(project)
      @project = project
    end

    def allowance
      @maximum_number_of_vulnerabilities ||=
        project_limit ||
        root_ancestor_limit ||
        application_wide_limit ||
        Float::INFINITY
    end

    def validate!
      return true unless quota_enabled?

      if full?
        store_over_usage

        false
      else
        clear_over_usage

        true
      end
    end

    def exceeded?
      return false unless quota_enabled?

      with_redis { |redis| redis.exists?(redis_state_key) }
    end

    def full?
      return false unless quota_enabled?

      quota_usage >= 100
    end

    def critical?
      return false unless quota_enabled?

      quota_usage > CRITICAL_QUOTA_THRESHOLD
    end

    private

    attr_reader :project

    delegate :security_statistics, :project_setting, :root_ancestor, to: :project, private: true
    delegate :vulnerability_count, to: :security_statistics, private: true

    def store_over_usage
      with_redis { |redis| redis.set(redis_state_key, true) }
    end

    def clear_over_usage
      with_redis { |redis| redis.del(redis_state_key) }
    end

    def with_redis
      Gitlab::Redis::SharedState.with { |redis| yield redis }
    end

    def redis_state_key
      "projects:#{project.id}:vulnerability_quota:over_usage"
    end

    def quota_usage
      100 * vulnerability_count / allowance
    end

    def project_limit
      project_setting.max_number_of_vulnerabilities
    end

    def root_ancestor_limit
      root_ancestor.namespace_limit.max_number_of_vulnerabilities_per_project
    end

    def application_wide_limit
      ::Gitlab::CurrentSettings.current_application_settings.max_number_of_vulnerabilities_per_project
    end

    def quota_enabled?
      ::Feature.enabled?(:limit_number_of_vulnerabilities_per_project, project)
    end
  end
end
