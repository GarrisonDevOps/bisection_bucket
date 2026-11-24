# frozen_string_literal: true

module EE
  module DependencyProxy
    module Blob
      extend ActiveSupport::Concern

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :dependency_proxy_blob_state)

        with_replicator Geo::DependencyProxyBlobReplicator

        has_one :dependency_proxy_blob_state,
          autosave: false,
          inverse_of: :dependency_proxy_blob,
          class_name: 'Geo::DependencyProxyBlobState',
          foreign_key: :dependency_proxy_blob_id

        scope :group_id_in, ->(ids) { joins(:group).merge(::Namespace.id_in(ids)) }

        def verification_state_object
          dependency_proxy_blob_state
        end
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        override :selective_sync_scope
        def selective_sync_scope(node, **params)
          replicables = params.fetch(:replicables, all)
          replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

          return replicables unless node.selective_sync?

          replicables.group_id_in(node.namespaces_for_group_owned_replicables.select(:id))
        end

        override :verification_state_table_class
        def verification_state_table_class
          Geo::DependencyProxyBlobState
        end
      end

      def dependency_proxy_blob_state
        super || build_dependency_proxy_blob_state
      end
    end
  end
end
