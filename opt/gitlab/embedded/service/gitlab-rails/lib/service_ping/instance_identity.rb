# frozen_string_literal: true

module ServicePing
  class InstanceIdentity
    def self.to_h
      new.to_h
    end

    def to_h
      {
        instance_id: ::Gitlab::GlobalAnonymousId.instance_id,
        unique_instance_id: unique_instance_id,
        host_name: Gitlab.config.gitlab.host,
        instance_version: Gitlab.version_info.to_s
      }
    end

    private

    def unique_instance_id
      ::Gitlab::GlobalAnonymousId.instance_uuid
    end
  end
end

ServicePing::InstanceIdentity.prepend_mod
