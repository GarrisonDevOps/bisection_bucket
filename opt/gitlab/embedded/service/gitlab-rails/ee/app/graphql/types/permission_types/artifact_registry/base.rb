# frozen_string_literal: true

module Types
  module PermissionTypes
    module ArtifactRegistry
      class Base < ::Types::PermissionTypes::BasePermissionType # rubocop:disable GraphQL/GraphqlName -- abstract; each subclass names its own type
        include Gitlab::Utils::StrongMemoize

        Block = Struct.new(:verdicts, :declaring_type, keyword_init: true)

        # A block reaches the schema as a bare struct with no policy class and no organization to
        # delegate to, so dropping the organization-rooted repository field's `skip_type_authorization`
        # would raise in `DeclarativePolicy.class_for` -- a 500, not a 403. Declared so the type states it.
        authorize :read_artifact_registry

        # A permissions block owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :parent_authorizes

        def self.verdict_field(action, **kwargs)
          permission_field(action, **kwargs)
          define_method(action) { allowed?(action) }
        end

        private

        def allowed?(action)
          return false unless served_verdicts

          served_verdicts.allowed?(action)
        end

        def served_verdicts
          verdicts = object.verdicts
          return verdicts if verdicts&.complete?

          if verdicts.nil?
            ::ArtifactRegistry::Permissions::VerdictReport.defect(scope: object.declaring_type)
          elsif verdicts.absent?
            ::ArtifactRegistry::Permissions::VerdictReport.absent(verdicts)
          else
            ::ArtifactRegistry::Permissions::VerdictReport.drift(verdicts)
          end

          nil
        end
        strong_memoize_attr :served_verdicts
      end
    end
  end
end
