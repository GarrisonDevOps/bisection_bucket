# frozen_string_literal: true

module Geo
  # Generates the Geo SSF (self-service framework) boilerplate for a new Git repository replicator.
  # See the USAGE file or run `rails g geo:repository_replicator --help`.
  #
  # Repository types wrap an existing domain model (wired in place by the base's create_model), use
  # RepositoryReplicatorStrategy, and replicate a Git repository rather than a blob. All the
  # repository-specific behavior lives here; the base stays type-agnostic.
  class RepositoryReplicatorGenerator < ReplicatorGenerator
    source_root File.expand_path('templates', __dir__)

    desc 'Generates Geo SSF replication and verification boilerplate for a new Git repository replicator.'

    private

    def replicator_model_template
      'models/repository_replicator.rb.tt'
    end

    def replicator_spec_template
      'specs/repository_replicator_spec.rb.tt'
    end

    # Repository types must not snapshot object pools, and need a state builder so
    # verification_state_object always returns a record.
    def model_extra_prepended_methods
      <<~RUBY
        # Geo prefers repository snapshotting; returning nil avoids snapshotting object pools,
        # which can cause data loss. Remove only if this type genuinely uses pools.
        def pool_repository
          nil
        end

        def #{file_name}_state
          super || build_#{file_name}_state
        end
      RUBY
    end

    def extra_framework_patches
      say_status(:todo, "Add a `when <Container>` branch for #{class_name} to log_geo_updated_event " \
        "in ee/app/models/ee/repository.rb (container-specific; not auto-generated)", :yellow)
    end

    def print_model_next_steps
      super

      say_status(:todo, "Implement the #repository method and #{class_name}.selective_sync_scope " \
        "correctly for this type", :yellow)
      say_status(:todo, "Decide housekeeping_enabled?, handle repository removal " \
        "(geo_handle_after_destroy), and update Gitlab::GitAccess<Type> if reachable over Git", :yellow)
      say_status(:todo, "If the model's update timestamp is not updated_at, set " \
        "self.model_updated_last in #{registry_class_name}", :yellow)
    end
  end
end
