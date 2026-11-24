# frozen_string_literal: true

require_relative "glaz/version"
require_relative 'glaz/loader'
require "proto/service_pb"
require "proto/govern_pb"

load_rust_extension

require_relative "glaz/engine"
require_relative "glaz/govern_policy_engine"

module Gitlab
  module Glaz
    module_function

    # Returns the default roles embedded in the native extension at build time,
    # sourced from the glaz-roles crate's roles/**/*.yml definitions. Each entry
    # is a hash:
    # { id: String, key: String, name: String, permissions: Array<String> }.
    #
    # :key is the role's stable machine identifier (e.g. "artifact_admin"):
    # reference a role by it rather than hardcoding :id or matching on :name,
    # which is human-facing and may be reworded.
    def roles
      @roles ||= ::Glaz.roles.each do |role|
        role[:permissions].freeze
        role.freeze
      end.freeze
    end

    # Returns GovernPolicyEngine.shared, the engine configured through
    # GovernPolicyEngine.policy_store_url= / GLAZ_POLICY_STORE_URL. It is
    # rebuilt when that configuration changes, so call this each time rather
    # than caching the result. Not needed when #evaluate gets +policies:+.
    def govern_policy_engine
      GovernPolicyEngine.shared
    end
  end
end
