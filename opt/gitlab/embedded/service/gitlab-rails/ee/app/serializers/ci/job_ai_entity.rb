# frozen_string_literal: true

module Ci
  class JobAiEntity < ::Ci::JobEntity
    include Gitlab::Llm::Chain::Concerns::JobLoggable

    # The trace is maintainer-only for restricted artifacts; gate it by :read_build_trace, not :read_build.
    READ_BUILD_TRACE = ->(job, options) { Ability.allowed?(options[:user], :read_build_trace, job) }

    expose :job_log, if: READ_BUILD_TRACE do |_job, options|
      job_log&.last(options[:content_limit])
    end
  end
end
