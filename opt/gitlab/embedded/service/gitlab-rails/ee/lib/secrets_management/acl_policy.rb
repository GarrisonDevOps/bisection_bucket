# frozen_string_literal: true

module SecretsManagement
  class AclPolicy
    # The name of this policy.
    attr_accessor :name

    # The set of paths granted by this policy. Each item in this map should be
    # an instance of AclPolicyPath.
    attr_accessor :paths

    def self.build_from_hash(name, object)
      paths = {}

      if !object.nil? && object.key?("path")
        object["path"].each_pair do |path, contents|
          paths[path] = AclPolicyPath.build_from_hash(path, contents)
        end
      end

      new(name, paths)
    end

    def initialize(name, paths = {})
      self.name = name
      self.paths = paths
    end

    def to_openbao_attributes
      # We have to reorganize the internal representation to match the
      # hcl-equivalent JSON format. Note that hcl2json incorrectly adds
      # additional arrays.
      #
      # See also: https://github.com/hashicorp/vault/issues/582

      ret = {
        path: {}
      }

      paths.each_pair do |path, value|
        ret[:path][path] = value.to_openbao_attributes
      end

      ret
    end

    def add_capability(path, cap, user: nil)
      paths[path] = AclPolicyPath.new(path, user: user) unless paths.key?(path)

      paths[path].capabilities.add(cap)
      paths[path].granted_by = user.id if user.present?
    end

    def remove_capability(path, cap)
      return unless paths.key?(path)

      paths[path].capabilities.delete(cap)

      return unless paths[path].capabilities.empty?

      paths.delete(path)
    end
  end
end
