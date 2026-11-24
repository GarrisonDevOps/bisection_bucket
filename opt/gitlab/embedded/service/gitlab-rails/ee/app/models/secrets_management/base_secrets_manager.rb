# frozen_string_literal: true

module SecretsManagement
  class BaseSecretsManager < ApplicationRecord
    include Gitlab::InternalEventsTracking
    include SecretsManagers::PipelineHelper
    include SecretsManagers::UserHelper
    include SecretsManagers::ApiHelper

    self.abstract_class = true

    STATUSES = {
      provisioning: 0,
      active: 1,
      deprovisioning: 2
    }.freeze

    state_machine :status, initial: :provisioning do
      state :provisioning, value: STATUSES[:provisioning]
      state :active, value: STATUSES[:active]
      state :deprovisioning, value: STATUSES[:deprovisioning]

      event :activate do
        transition all - [:active] => :active
      end

      event :initiate_deprovision do
        transition active: :deprovisioning
      end
    end

    scope :active, -> { where(status: STATUSES[:active]) }
    scope :for_root_namespace, ->(root_namespace_id) { where(root_namespace_id: root_namespace_id) }

    # Server Configuration
    def self.jwt_issuer
      Gitlab.config.gitlab.base_url
    end

    def self.internal_server_url
      if Gitlab.config.has_key?("openbao") && Gitlab.config.openbao.has_key?("internal_url")
        return Gitlab.config.openbao.internal_url
      end

      server_url
    end

    def self.server_url
      return SecretsManagement::OpenbaoTestSetup::SERVER_ADDRESS_WITH_HTTP if Rails.env.test?
      return Gitlab.config.openbao.url if Gitlab.config.has_key?("openbao") && Gitlab.config.openbao.has_key?("url")

      default_openbao_server_url
    end

    def self.jwt_audience
      return SecretsManagement::OpenbaoTestSetup::SERVER_ADDRESS_WITH_HTTP if Rails.env.test?

      if jwt_audience_configured?
        Gitlab.config.openbao.jwt_audience
      else
        server_url
      end
    end

    def self.jwt_audience_configured?
      Gitlab.config.has_key?("openbao") &&
        Gitlab.config.openbao.has_key?("jwt_audience") &&
        Gitlab.config.openbao.jwt_audience.present?
    end

    def self.default_openbao_server_url
      "#{Gitlab.config.gitlab.protocol}://#{Gitlab.config.gitlab.host}:8200"
    end

    # Load balancer sticking key for the activation; see #refreshed_after_activation.
    def self.sticking_namespace
      raise NotImplementedError
    end

    def scope_name
      self.class.name.demodulize.delete_suffix('SecretsManager').underscore
    end

    def sticking_id
      raise NotImplementedError
    end

    def stick_activation!
      self.class.sticking.stick(self.class.sticking_namespace, sticking_id)
    end

    def active_after_refresh?
      refreshed_after_activation&.active? || false
    end

    # The provisioning worker activates the row from Sidekiq, so no web request
    # is stuck to the primary for that write and a lagging replica keeps
    # answering `provisioning` (https://gitlab.com/gitlab-org/gitlab/-/work_items/633014).
    # While the row reads `provisioning`, ask the load balancer for a host that
    # has the activation recorded by `stick_activation!` and reload from it.
    # Returns nil when the row no longer exists there.
    def refreshed_after_activation
      return self unless provisioning? && persisted?
      return self if self.class.load_balancer.primary_only?

      self.class.sticking.find_caught_up_replica(self.class.sticking_namespace, sticking_id)
      reload # rubocop:disable Cop/ActiveRecordAssociationReload -- the status column itself must be re-read; reset only drops association caches
    rescue ActiveRecord::RecordNotFound
      nil
    end

    # Prepares for the trigger-based design (gitlab-org/gitlab#600290)
    # where the SM row may be deleted before OpenBao cleanup completes;
    # the maintenance task becomes the only durable signal of an
    # in-flight deprovision.
    def effective_status
      return STATUSES[:deprovisioning] if pending_deprovision_task?

      status
    end

    def pending_deprovision_task?
      raise NotImplementedError
    end

    private_class_method :default_openbao_server_url, :jwt_audience_configured?

    private

    def aud
      self.class.jwt_audience
    end

    def hex(value)
      value.unpack1('H*')
    end
  end
end
