# frozen_string_literal: true

module SecretsManagement
  class PipelineJwt < Gitlab::Ci::JwtV2
    private

    def predefined_claims
      super.merge(
        secrets_manager_scope: 'pipeline',
        project_group_ids: project_group_ids
      )
    end

    def project_group_ids
      source_project.group&.self_and_ancestors&.pluck(:id)&.map(&:to_s) || []
    end

    # OpenBao validates project identity via project_id and project_group_ids claims,
    # not the sub prefix, so the burned-path check provides no security benefit here.
    def verify_path_not_burned!; end

    # Must match the bound_issuer of the pipeline auth mounts, which can differ from a
    # custom ci_id_tokens.issuer_url set for other ID token consumers such as AWS.
    def issuer_url
      SecretsManagement::BaseSecretsManager.jwt_issuer
    end
  end
end
