# frozen_string_literal: true

require 'time'

module SecretsManagement
  class AclPolicyPath
    attr_accessor :path, :capabilities, :granted_by, :denied_parameters, :required_parameters, :allowed_parameters,
      :expired_at

    # Individual capabilities
    CAP_CREATE = "create"
    CAP_UPDATE = "update"
    CAP_PATCH = "patch"
    CAP_DELETE = "delete"
    CAP_LIST = "list"

    def self.build_from_hash(path, object)
      capabilities = Set.new(object["capabilities"]) if object.key?("capabilities")

      ret = new(path, capabilities)
      ret.allowed_parameters = object["allowed_parameters"] if object.key?("allowed_parameters")
      ret.denied_parameters = object["denied_parameters"] if object.key?("denied_parameters")
      ret.required_parameters = Set.new(object["required_parameters"]) if object.key?("required_parameters")
      ret.granted_by = object["comment"] if object.key?("comment")
      ret.expired_at = object["expiration"] if object.key?("expiration")

      ret
    end

    def initialize(path, capabilities = [], user: nil)
      self.path = path

      self.capabilities = Set.new(capabilities)
      self.granted_by = user.id if user.present?

      # Most callers will not need to set parameter restrictions.
      self.allowed_parameters = {}
      self.denied_parameters = {}
      self.required_parameters = Set.new
    end

    def to_openbao_attributes
      ret = {}
      ret["capabilities"] = capabilities unless capabilities.empty?
      ret["comment"] = granted_by unless granted_by.nil?
      ret["expiration"] = expired_at.to_s if expired_at

      ret["allowed_parameters"] = allowed_parameters unless allowed_parameters.empty?
      ret["denied_parameters"] = denied_parameters unless denied_parameters.empty?
      ret["required_parameters"] = required_parameters unless required_parameters.empty?

      ret
    end
  end
end
