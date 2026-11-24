# frozen_string_literal: true

module GoogleCloud
  class Jwt < ::Gitlab::Ci::JwtBase
    extend ::Gitlab::Utils::Override

    JWT_OPTIONS_ERROR = 'This jwt needs jwt claims audience and target_audience to be set.'

    def initialize(project:, user:, claims:)
      super()

      raise ArgumentError, JWT_OPTIONS_ERROR if claims[:audience].blank? || claims[:target_audience].blank?

      @claims = claims
      @project = project
      @user = user
    end

    private

    attr_reader :project, :user, :claims

    delegate :root_namespace, to: :project

    override :subject
    def subject
      "project_#{project.id}_user_#{user.id}"
    end

    def predefined_claims
      project_claims.merge(
        root_namespace_path: root_namespace.full_path,
        root_namespace_id: root_namespace.id.to_s,
        target_audience: claims[:target_audience]
      )
    end

    def project_claims
      ::JSONWebToken::UserProjectTokenClaims
       .new(project: project, user: user)
       .generate
    end

    override :issuer
    def issuer
      Gitlab.config.gitlab.url
    end

    override :audience
    def audience
      claims[:audience]
    end
  end
end
