# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    module NetworkPolicyDomains
      # Domains taken from https://code.claude.com/docs/en/claude-code-on-the-web#default-allowed-domains,
      # plus cdn.registry.gitlab-static.net, which registry.gitlab.com redirects blob pulls to.
      VERSION_CONTROL_DOMAINS = %w[
        github.com
        www.github.com
        api.github.com
        npm.pkg.github.com
        raw.githubusercontent.com
        pkg-npm.githubusercontent.com
        objects.githubusercontent.com
        release-assets.githubusercontent.com
        codeload.github.com
        avatars.githubusercontent.com
        camo.githubusercontent.com
        gist.github.com
        gitlab.com
        www.gitlab.com
        registry.gitlab.com
        cdn.registry.gitlab-static.net
        bitbucket.org
        www.bitbucket.org
        api.bitbucket.org
      ].freeze

      CONTAINER_REGISTRY_DOMAINS = %w[
        registry-1.docker.io
        auth.docker.io
        index.docker.io
        hub.docker.com
        www.docker.com
        production.cloudflare.docker.com
        download.docker.com
        gcr.io
        *.gcr.io
        ghcr.io
        mcr.microsoft.com
        *.data.mcr.microsoft.com
        public.ecr.aws
      ].freeze

      CLOUD_DOMAINS = %w[
        cloud.google.com
        accounts.google.com
        gcloud.google.com
        storage.googleapis.com
        compute.googleapis.com
        container.googleapis.com
        artifactregistry.googleapis.com
        cloudresourcemanager.googleapis.com
        oauth2.googleapis.com
        www.googleapis.com
        login.microsoftonline.com
        packages.microsoft.com
        dotnet.microsoft.com
        dot.net
        dev.azure.com
        s3.amazonaws.com
        *.s3.amazonaws.com
        *.codeartifact.amazonaws.com
        *.s3.api.aws
        *.codeartifact.api.aws
        download.oracle.com
        yum.oracle.com
      ].freeze

      JAVASCRIPT_DOMAINS = %w[
        registry.npmjs.org
        www.npmjs.com
        www.npmjs.org
        npmjs.com
        npmjs.org
        yarnpkg.com
        registry.yarnpkg.com
      ].freeze

      PYTHON_DOMAINS = %w[
        pypi.org
        www.pypi.org
        files.pythonhosted.org
        pythonhosted.org
        test.pypi.org
        pypi.python.org
        pypa.io
        www.pypa.io
      ].freeze

      RUBY_DOMAINS = %w[
        rubygems.org
        www.rubygems.org
        api.rubygems.org
        index.rubygems.org
        ruby-lang.org
        www.ruby-lang.org
        rubyonrails.org
        www.rubyonrails.org
        rvm.io
        get.rvm.io
      ].freeze

      RUST_DOMAINS = %w[
        crates.io
        www.crates.io
        index.crates.io
        static.crates.io
        rustup.rs
        static.rust-lang.org
        www.rust-lang.org
      ].freeze

      GO_DOMAINS = %w[
        proxy.golang.org
        sum.golang.org
        index.golang.org
        golang.org
        www.golang.org
        goproxy.io
        pkg.go.dev
      ].freeze

      JVM_DOMAINS = %w[
        maven.org
        repo.maven.org
        central.maven.org
        repo1.maven.org
        jcenter.bintray.com
        gradle.org
        www.gradle.org
        services.gradle.org
        plugins.gradle.org
        kotlin.org
        www.kotlin.org
        spring.io
        repo.spring.io
      ].freeze

      PACKAGE_MANAGEMENT_DOMAINS = %w[
        packagist.org
        www.packagist.org
        repo.packagist.org
        nuget.org
        www.nuget.org
        api.nuget.org
        pub.dev
        api.pub.dev
        hex.pm
        www.hex.pm
        cpan.org
        www.cpan.org
        metacpan.org
        www.metacpan.org
        api.metacpan.org
        cocoapods.org
        www.cocoapods.org
        cdn.cocoapods.org
        haskell.org
        www.haskell.org
        hackage.haskell.org
        swift.org
        www.swift.org
      ].freeze

      LINUX_DOMAINS = %w[
        archive.ubuntu.com
        security.ubuntu.com
        ubuntu.com
        www.ubuntu.com
        *.ubuntu.com
        ppa.launchpad.net
        launchpad.net
        www.launchpad.net
      ].freeze

      DEV_DOMAINS = %w[
        dl.k8s.io
        pkgs.k8s.io
        k8s.io
        www.k8s.io
        releases.hashicorp.com
        apt.releases.hashicorp.com
        rpm.releases.hashicorp.com
        archive.releases.hashicorp.com
        hashicorp.com
        www.hashicorp.com
        repo.anaconda.com
        conda.anaconda.org
        anaconda.org
        www.anaconda.com
        anaconda.com
        continuum.io
        apache.org
        www.apache.org
        archive.apache.org
        downloads.apache.org
        eclipse.org
        www.eclipse.org
        download.eclipse.org
        nodejs.org
        www.nodejs.org
      ].freeze

      CONTENT_DELIVERY_DOMAINS = %w[
        sourceforge.net
        *.sourceforge.net
        packagecloud.io
        *.packagecloud.io
      ].freeze

      SCHEMA_DOMAINS = %w[
        json-schema.org
        www.json-schema.org
        json.schemastore.org
        www.schemastore.org
      ].freeze

      MCP_DOMAINS = %w[
        *.modelcontextprotocol.io
      ].freeze

      def self.recommended_allowed_domains
        (VERSION_CONTROL_DOMAINS + CONTAINER_REGISTRY_DOMAINS + CLOUD_DOMAINS + JAVASCRIPT_DOMAINS + PYTHON_DOMAINS +
          RUBY_DOMAINS + RUST_DOMAINS + GO_DOMAINS + JVM_DOMAINS + PACKAGE_MANAGEMENT_DOMAINS + LINUX_DOMAINS +
          DEV_DOMAINS + CONTENT_DELIVERY_DOMAINS + SCHEMA_DOMAINS + MCP_DOMAINS).freeze
      end
    end
  end
end
